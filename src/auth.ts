import { randomUUID, randomBytes } from "node:crypto";
import type { Response } from "express";
import type { OAuthServerProvider, AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type {
  OAuthClientInformationFull,
  OAuthTokens,
  OAuthTokenRevocationRequest,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { logger } from "./logger.js";
import { redis, redisKey } from "./redis.js";
import { encrypt, decrypt } from "./crypto.js";

class OAuthValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OAuthValidationError";
  }
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// TTLs in seconds
const TTL_CSRF = 10 * 60;               // 10 minutes
const TTL_AUTH_CODE = 5 * 60;            // 5 minutes
const TTL_ACCESS_TOKEN = 3600 * 24 * 7;  // 7 days — sliding, refreshed on each use
const TTL_REFRESH_TOKEN = 3600 * 24 * 7; // 7 days — sliding, refreshed on rotation
const TTL_CLIENT = 3600 * 24 * 90;       // 90 days, refreshed on use

// Allowed redirect URI hosts for dynamic client registration.
// By default only loopback addresses are permitted (standard for native OAuth clients).
// Set OAUTH_ALLOWED_REDIRECT_HOSTS to a comma-separated list to allow additional hosts.
const ALLOWED_REDIRECT_HOSTS = new Set([
  "localhost",
  "127.0.0.1",
  "::1",
  ...(process.env.OAUTH_ALLOWED_REDIRECT_HOSTS || "")
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean),
]);

function isAllowedRedirectUri(uri: string): boolean {
  try {
    const parsed = new URL(uri);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return false;
    }
    return ALLOWED_REDIRECT_HOSTS.has(parsed.hostname.toLowerCase());
  } catch {
    return false;
  }
}

interface AuthCodeData {
  clientId: string;
  codeChallenge: string;
  redirectUri: string;
  redashApiKey: string;
  state?: string;
}

interface AccessTokenData {
  clientId: string;
  redashApiKey: string;
}

interface RefreshTokenData {
  clientId: string;
  redashApiKey: string;
}

class RedashClientsStore implements OAuthRegisteredClientsStore {
  async getClient(
    clientId: string
  ): Promise<OAuthClientInformationFull | undefined> {
    const data = await redis.get(redisKey("client", clientId));
    if (!data) return undefined;
    return JSON.parse(data) as OAuthClientInformationFull;
  }

  async registerClient(
    client: OAuthClientInformationFull
  ): Promise<OAuthClientInformationFull> {
    // Validate redirect URIs against allowlist to prevent phishing via
    // attacker-controlled redirect targets.
    const uris = client.redirect_uris ?? [];
    if (uris.length === 0) {
      throw new Error("At least one redirect_uri is required");
    }
    for (const uri of uris) {
      if (!isAllowedRedirectUri(uri.toString())) {
        logger.warning(
          `Client registration rejected: disallowed redirect_uri ${uri}`
        );
        throw new Error(
          `redirect_uri not allowed: only loopback addresses (localhost, 127.0.0.1) are permitted`
        );
      }
    }

    const clientId = client.client_id ?? randomUUID();
    const clientSecret = randomBytes(32).toString("hex");
    const full: OAuthClientInformationFull = {
      ...client,
      client_id: clientId,
      client_secret: clientSecret,
      client_id_issued_at: Math.floor(Date.now() / 1000),
    };
    await redis.set(
      redisKey("client", clientId),
      JSON.stringify(full),
      "EX",
      TTL_CLIENT
    );
    logger.info(`Registered OAuth client: ${clientId}`);
    return full;
  }
}

export class RedashOAuthProvider implements OAuthServerProvider {
  readonly clientsStore = new RedashClientsStore();

  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response
  ): Promise<void> {
    const csrfToken = randomBytes(24).toString("hex");
    await redis.set(redisKey("csrf", csrfToken), "1", "EX", TTL_CSRF);

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Redash MCP - Authorization</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 480px; margin: 80px auto; padding: 0 20px; background: #f5f5f5; }
    .card { background: white; border-radius: 12px; padding: 32px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
    h1 { font-size: 1.4em; margin: 0 0 8px; }
    p { color: #666; font-size: 0.9em; margin: 0 0 24px; }
    label { display: block; font-weight: 600; margin-bottom: 6px; font-size: 0.9em; }
    input[type="password"] { width: 100%; padding: 10px 12px; border: 1px solid #ddd; border-radius: 8px; font-size: 1em; box-sizing: border-box; }
    input[type="password"]:focus { outline: none; border-color: #4a90d9; box-shadow: 0 0 0 3px rgba(74,144,217,0.15); }
    button { width: 100%; padding: 12px; background: #4a90d9; color: white; border: none; border-radius: 8px; font-size: 1em; font-weight: 600; cursor: pointer; margin-top: 20px; }
    button:hover { background: #3a7bc8; }
    .hint { font-size: 0.8em; color: #999; margin-top: 6px; }
    .client-name { color: #4a90d9; font-weight: 600; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Redash MCP Authorization</h1>
    <p>Enter your Redash API key to authorize <span class="client-name">${escapeHtml(client.client_name || "the application")}</span>.</p>
    <form method="POST" action="/authorize/submit">
      <input type="hidden" name="csrf_token" value="${csrfToken}">
      <input type="hidden" name="client_id" value="${escapeHtml(client.client_id)}">
      <input type="hidden" name="redirect_uri" value="${escapeHtml(params.redirectUri)}">
      <input type="hidden" name="code_challenge" value="${escapeHtml(params.codeChallenge)}">
      <input type="hidden" name="state" value="${escapeHtml(params.state || "")}">
      <label for="api_key">Redash API Key</label>
      <input type="password" id="api_key" name="api_key" placeholder="Enter your Redash API key" required autofocus>
      <p class="hint">Find your API key in Redash: Profile icon (bottom-left) > API Key</p>
      <button type="submit">Authorize</button>
    </form>
  </div>
</body>
</html>`;
    res.setHeader("Content-Type", "text/html");
    res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.send(html);
  }

  async challengeForAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string
  ): Promise<string> {
    try {
      const data = await redis.get(redisKey("code", authorizationCode));
      if (!data) {
        logger.warning("PKCE challenge requested for invalid auth code");
        throw new OAuthValidationError("Invalid authorization code");
      }
      const code: AuthCodeData = JSON.parse(data);
      return code.codeChallenge;
    } catch (error) {
      if (error instanceof OAuthValidationError) throw error;
      logger.error(`challengeForAuthorizationCode failed: ${error instanceof Error ? error.message : String(error)}`);
      throw new Error("Failed to retrieve authorization code challenge");
    }
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string
  ): Promise<OAuthTokens> {
    try {
      const key = redisKey("code", authorizationCode);
      // Atomic read-and-delete: prevents a concurrent request from reusing the same code
      const data = await redis.getdel(key);
      if (!data) {
        logger.warning(`Auth code exchange failed: invalid code for client ${client.client_id}`);
        throw new OAuthValidationError("Invalid authorization code");
      }
      const code: AuthCodeData = JSON.parse(data);

      if (code.clientId !== client.client_id) {
        logger.warning(`Auth code exchange failed: client mismatch (expected ${code.clientId}, got ${client.client_id})`);
        throw new OAuthValidationError("Client mismatch");
      }
      if (redirectUri && code.redirectUri !== redirectUri) {
        logger.warning(`Auth code exchange failed: redirect_uri mismatch for client ${client.client_id}`);
        throw new OAuthValidationError("redirect_uri mismatch");
      }

      const accessToken = randomBytes(32).toString("hex");
      const refreshToken = randomBytes(32).toString("hex");
      const decryptedApiKey = decrypt(code.redashApiKey);

      const tokenData: AccessTokenData = {
        clientId: client.client_id,
        redashApiKey: encrypt(decryptedApiKey),
      };
      const refreshData: RefreshTokenData = {
        clientId: client.client_id,
        redashApiKey: encrypt(decryptedApiKey),
      };

      const pipeline = redis.multi();
      pipeline.set(
        redisKey("token", accessToken),
        JSON.stringify(tokenData),
        "EX",
        TTL_ACCESS_TOKEN
      );
      pipeline.set(
        redisKey("refresh", refreshToken),
        JSON.stringify(refreshData),
        "EX",
        TTL_REFRESH_TOKEN
      );
      pipeline.expire(redisKey("client", client.client_id), TTL_CLIENT);
      const results = await pipeline.exec();
      if (!results || results.some(([err]) => err !== null)) {
        throw new Error("Redis pipeline partially failed");
      }

      logger.info(`Auth code exchanged for client ${client.client_id}`);

      return {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: TTL_ACCESS_TOKEN,
        refresh_token: refreshToken,
      };
    } catch (error) {
      if (error instanceof OAuthValidationError) throw error;
      logger.error(`exchangeAuthorizationCode failed: ${error instanceof Error ? error.message : String(error)}`);
      throw new Error("Token exchange failed due to an internal error");
    }
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string
  ): Promise<OAuthTokens> {
    try {
      const key = redisKey("refresh", refreshToken);
      // Atomic read-and-delete: prevents concurrent reuse of the same refresh token
      const data = await redis.getdel(key);
      if (!data) {
        logger.warning(`Refresh token exchange failed: invalid token for client ${client.client_id}`);
        throw new OAuthValidationError("Invalid refresh token");
      }
      const stored: RefreshTokenData = JSON.parse(data);

      if (stored.clientId !== client.client_id) {
        logger.warning(`Refresh token exchange failed: client mismatch (expected ${stored.clientId}, got ${client.client_id})`);
        throw new OAuthValidationError("Client mismatch");
      }

      const accessToken = randomBytes(32).toString("hex");
      const newRefreshToken = randomBytes(32).toString("hex");
      const decryptedApiKey = decrypt(stored.redashApiKey);

      const tokenData: AccessTokenData = {
        clientId: client.client_id,
        redashApiKey: encrypt(decryptedApiKey),
      };
      const refreshData: RefreshTokenData = {
        clientId: client.client_id,
        redashApiKey: encrypt(decryptedApiKey),
      };

      // Atomic write: all-or-nothing to prevent partial state on failure
      const pipeline = redis.multi();
      pipeline.set(
        redisKey("token", accessToken),
        JSON.stringify(tokenData),
        "EX",
        TTL_ACCESS_TOKEN
      );
      pipeline.set(
        redisKey("refresh", newRefreshToken),
        JSON.stringify(refreshData),
        "EX",
        TTL_REFRESH_TOKEN
      );
      pipeline.expire(redisKey("client", client.client_id), TTL_CLIENT);
      const results = await pipeline.exec();
      if (!results || results.some(([err]) => err !== null)) {
        throw new Error("Redis pipeline partially failed");
      }

      logger.info(`Refresh token rotated for client ${client.client_id}`);

      return {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: TTL_ACCESS_TOKEN,
        refresh_token: newRefreshToken,
      };
    } catch (error) {
      if (error instanceof OAuthValidationError) throw error;
      logger.error(`exchangeRefreshToken failed: ${error instanceof Error ? error.message : String(error)}`);
      throw new Error("Token refresh failed due to an internal error");
    }
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    try {
      const key = redisKey("token", token);
      const data = await redis.get(key);
      if (!data) {
        logger.warning("Access token verification failed: invalid token");
        throw new OAuthValidationError("Invalid access token");
      }
      const stored: AccessTokenData = JSON.parse(data);

      // Sliding expiry: reset TTL on every successful verification
      await Promise.all([
        redis.expire(key, TTL_ACCESS_TOKEN),
        redis.expire(redisKey("client", stored.clientId), TTL_CLIENT),
      ]);

      logger.debug(`Access token verified for client ${stored.clientId}`);

      return {
        token,
        clientId: stored.clientId,
        scopes: [],
        expiresAt: Math.floor(Date.now() / 1000) + TTL_ACCESS_TOKEN,
        extra: { redashApiKey: decrypt(stored.redashApiKey) },
      };
    } catch (error) {
      if (error instanceof OAuthValidationError) throw error;
      logger.error(`verifyAccessToken failed: ${error instanceof Error ? error.message : String(error)}`);
      throw new Error("Token verification failed due to an internal error");
    }
  }

  async revokeToken(
    client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest
  ): Promise<void> {
    try {
      await Promise.all([
        redis.del(redisKey("token", request.token)),
        redis.del(redisKey("refresh", request.token)),
      ]);
      logger.info(`Token revoked for client ${client.client_id}`);
    } catch (error) {
      logger.error(`revokeToken failed: ${error instanceof Error ? error.message : String(error)}`);
      // Revocation is best-effort per RFC 7009 — do not throw
    }
  }

  async handleAuthorizeSubmit(
    csrfToken: string,
    clientId: string,
    redirectUri: string,
    codeChallenge: string,
    state: string | undefined,
    redashApiKey: string,
    res: Response
  ): Promise<void> {
    try {
      // Atomically check and delete CSRF token
      const deleted = await redis.del(redisKey("csrf", csrfToken));
      if (deleted === 0) {
        logger.warning(`Authorization submit failed: invalid CSRF token for client ${clientId}`);
        res.status(403).send("Invalid or expired form submission. Please go back and try again.");
        return;
      }

      const clientData = await redis.get(redisKey("client", clientId));
      if (!clientData) {
        logger.warning(`Authorization submit failed: unknown client ${clientId}`);
        res.status(400).send("Invalid client_id");
        return;
      }
      const client: OAuthClientInformationFull = JSON.parse(clientData);

      const registeredUris = client.redirect_uris || [];
      if (!registeredUris.some((uri) => uri.toString() === redirectUri)) {
        logger.warning(`Authorization submit failed: invalid redirect_uri for client ${clientId}`);
        res.status(400).send("Invalid redirect_uri");
        return;
      }

      const code = randomBytes(16).toString("hex");
      const codeData: AuthCodeData = {
        clientId,
        codeChallenge,
        redirectUri,
        redashApiKey: encrypt(redashApiKey),
        state,
      };
      await redis.set(
        redisKey("code", code),
        JSON.stringify(codeData),
        "EX",
        TTL_AUTH_CODE
      );

      logger.info(`Auth code issued for client ${clientId}`);

      const url = new URL(redirectUri);
      url.searchParams.set("code", code);
      if (state) url.searchParams.set("state", state);
      res.redirect(302, url.toString());
    } catch (error) {
      logger.error(`handleAuthorizeSubmit failed: ${error instanceof Error ? error.message : String(error)}`);
      if (!res.headersSent) {
        res.status(500).send("Internal server error");
      }
    }
  }
}

export function getRedashApiKeyFromAuth(auth: AuthInfo): string {
  const apiKey = auth.extra?.redashApiKey;
  if (typeof apiKey !== "string" || !apiKey) {
    throw new Error("No Redash API key in auth info");
  }
  return apiKey;
}
