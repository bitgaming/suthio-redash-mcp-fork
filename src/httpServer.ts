import { createHmac, timingSafeEqual } from "node:crypto";
import express from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { createRedashClient } from "./redashClient.js";
import { createServer } from "./index.js";
import { logger } from "./logger.js";
import { RedashOAuthProvider, getRedashApiKeyFromAuth } from "./auth.js";
import { isEncryptionEnabled } from "./crypto.js";
import { connectRedis, redis } from "./redis.js";

const app = express();
const TRUST_PROXY = process.env.TRUST_PROXY ?? "1";
app.set("trust proxy", /^\d+$/.test(TRUST_PROXY) ? parseInt(TRUST_PROXY, 10) : TRUST_PROXY);
app.use(express.json());

const PORT = parseInt(process.env.PORT || "3000", 10);
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// --- Legacy auth (Claude Code with headers) ---

const AUTH_TOKENS = (process.env.MCP_AUTH_TOKENS || "")
  .split(",")
  .map((t) => t.trim())
  .filter(Boolean);

// HMAC both sides before comparing so the buffers are always 32 bytes,
// eliminating the timing leak from the length check that timingSafeEqual requires.
function hmacToken(token: string): Buffer {
  return createHmac("sha256", "redash-mcp-auth-compare").update(token).digest();
}

function isValidAuthToken(token: string): boolean {
  const tokenMac = hmacToken(token);
  return AUTH_TOKENS.some((t) => timingSafeEqual(hmacToken(t), tokenMac));
}

// --- OAuth auth (Claude Desktop Connectors) ---

const oauthProvider = new RedashOAuthProvider();

// Optional basic auth gate for the OAuth authorization page.
// When OAUTH_BASIC_AUTH_USER and OAUTH_BASIC_AUTH_PASS are set, the browser
// will prompt for credentials before showing the API key form. This prevents
// unauthenticated access to the authorization flow on public deployments.
const BASIC_AUTH_USER = process.env.OAUTH_BASIC_AUTH_USER || "";
const BASIC_AUTH_PASS = process.env.OAUTH_BASIC_AUTH_PASS || "";
const basicAuthEnabled = BASIC_AUTH_USER.length > 0 && BASIC_AUTH_PASS.length > 0;

function requireBasicAuth(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): void {
  if (!basicAuthEnabled) {
    next();
    return;
  }

  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("Basic ")) {
    const decoded = Buffer.from(authHeader.slice(6), "base64").toString();
    const colonIdx = decoded.indexOf(":");
    if (colonIdx !== -1) {
      const user = decoded.substring(0, colonIdx);
      const pass = decoded.substring(colonIdx + 1);
      // HMAC both sides to normalize buffer length, preventing timing leak
      const userMatch = timingSafeEqual(hmacToken(user), hmacToken(BASIC_AUTH_USER));
      const passMatch = timingSafeEqual(hmacToken(pass), hmacToken(BASIC_AUTH_PASS));
      if (userMatch && passMatch) {
        next();
        return;
      }
    }
  }

  logger.warning(`Basic auth failed for OAuth authorize from ${req.ip}`);
  res.setHeader("WWW-Authenticate", 'Basic realm="OAuth Authorization"');
  res.status(401).send("Unauthorized");
}

// Gate the OAuth authorization page with basic auth (before mcpAuthRouter handles it)
app.use("/authorize", requireBasicAuth);

// Mount OAuth discovery & token endpoints (public, no auth required)
app.use(
  mcpAuthRouter({
    provider: oauthProvider,
    issuerUrl: new URL(BASE_URL),
    baseUrl: new URL(BASE_URL),
    resourceServerUrl: new URL(`${BASE_URL}/mcp`),
    scopesSupported: [],
  })
);

// Handle the OAuth authorization form submission (basic auth gated)
app.use("/authorize/submit", express.urlencoded({ extended: false }));
app.post(
  "/authorize/submit",
  requireBasicAuth,
  async (req: express.Request, res: express.Response) => {
    const { csrf_token, client_id, redirect_uri, code_challenge, state, api_key } =
      req.body;
    if (!csrf_token || !client_id || !redirect_uri || !code_challenge || !api_key) {
      res.status(400).send("Missing required fields");
      return;
    }
    await oauthProvider.handleAuthorizeSubmit(
      csrf_token,
      client_id,
      redirect_uri,
      code_challenge,
      state || undefined,
      api_key,
      res
    );
  }
);

// --- Combined auth middleware ---
// Supports both legacy bearer+header auth (Claude Code) and OAuth (Claude Desktop)

const oauthBearerAuth = requireBearerAuth({ verifier: oauthProvider });

function combinedAuth(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): void {
  const authHeader = req.headers.authorization;

  // Try legacy auth: if the bearer token matches a configured MCP_AUTH_TOKEN,
  // use the X-Redash-API-Key header for the Redash API key.
  let legacyAuthAttempted = false;
  if (authHeader?.startsWith("Bearer ") && AUTH_TOKENS.length > 0) {
    const token = authHeader.slice(7);
    if (isValidAuthToken(token)) {
      const apiKey = req.headers["x-redash-api-key"] as string | undefined;
      if (!apiKey) {
        logger.warning(`Legacy auth: missing X-Redash-API-Key header from ${req.ip}`);
        res.status(400).json({ error: "Missing X-Redash-API-Key header" });
        return;
      }
      (req as any).redashApiKey = apiKey;
      next();
      return;
    }
    legacyAuthAttempted = true;
    logger.warning(`Legacy auth: invalid bearer token from ${req.ip}`);
  }

  // Fall through to OAuth bearer auth.
  oauthBearerAuth(req, res, (err?: any) => {
    if (err) {
      if (legacyAuthAttempted) {
        // Token did not match legacy auth or OAuth — give a clear error
        // instead of confusing WWW-Authenticate headers.
        logger.warning(`Auth failed from ${req.ip}: token is neither a valid legacy token nor a valid OAuth token`);
        res.status(401).json({
          error: "unauthorized",
          message: "Bearer token is not valid. Check that the token has not expired.",
        });
        return;
      }
      logger.warning(`OAuth auth failed from ${req.ip}: ${err instanceof Error ? err.message : String(err)}`);
      next(err);
      return;
    }
    try {
      const auth = (req as any).auth as AuthInfo;
      if (auth) {
        (req as any).redashApiKey = getRedashApiKeyFromAuth(auth);
      }
      next();
    } catch (e) {
      logger.warning(`OAuth auth: could not extract API key from token from ${req.ip}`);
      res.status(401).json({ error: "Could not extract Redash API key from token" });
    }
  });
}

// --- Routes ---

app.get("/health", (_req, res) => {
  const redisOk = redis.status === "ready";
  res.json({ status: redisOk ? "ok" : "degraded", redis: redis.status });
});

// MCP endpoint — stateless: each POST creates a fresh server + transport
app.post("/mcp", combinedAuth, async (req, res) => {
  const redashApiKey = (req as any).redashApiKey as string;

  const redashClient = createRedashClient(redashApiKey);
  const server = createServer(redashClient);
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined, // stateless
  });

  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    logger.error(
      `MCP request error: ${error instanceof Error ? error.message : String(error)}`
    );
    if (!res.headersSent) {
      res.status(500).json({ error: "Internal server error" });
    }
  } finally {
    try { await transport.close(); } catch (e) { logger.error(`Transport close error: ${e instanceof Error ? e.message : String(e)}`); }
    try { await server.close(); } catch (e) { logger.error(`Server close error: ${e instanceof Error ? e.message : String(e)}`); }
  }
});

// Reject GET/DELETE on /mcp (explicit methods instead of app.all to avoid
// accidentally catching POST if routes are reordered)
app.get("/mcp", (_req, res) => {
  res.status(405).json({ error: "Method not allowed. Use POST." });
});
app.delete("/mcp", (_req, res) => {
  res.status(405).json({ error: "Method not allowed. Use POST." });
});

async function main() {
  await connectRedis();

  const httpServer = app.listen(PORT, () => {
    logger.info(`HTTP MCP server listening on port ${PORT}`);
    logger.info(`Base URL: ${BASE_URL}`);
    logger.info(
      AUTH_TOKENS.length > 0
        ? `Legacy bearer auth enabled (${AUTH_TOKENS.length} token(s))`
        : "Legacy bearer auth disabled (no MCP_AUTH_TOKENS set)"
    );
    logger.info("OAuth 2.1 auth enabled for Claude Desktop Connectors");
    logger.info(
      isEncryptionEnabled()
        ? "API key encryption at rest enabled"
        : "WARNING: MCP_ENCRYPTION_KEY not set — API keys stored unencrypted in Redis"
    );
    logger.info(
      basicAuthEnabled
        ? "OAuth authorize page protected with basic auth"
        : "OAuth authorize page is open (set OAUTH_BASIC_AUTH_USER and OAUTH_BASIC_AUTH_PASS to enable basic auth)"
    );
  });

  function shutdown(signal: string) {
    logger.info(`Received ${signal}, shutting down gracefully...`);
    httpServer.close(() => {
      redis.quit().then(() => {
        logger.info("Shutdown complete");
        process.exit(0);
      }).catch(() => {
        process.exit(1);
      });
    });
    // Force exit if graceful shutdown takes too long
    setTimeout(() => {
      logger.error("Shutdown timed out, forcing exit");
      process.exit(1);
    }, 10_000).unref();
  }

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

main().catch((err) => {
  logger.error(`Failed to start server: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
