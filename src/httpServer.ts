import express from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { createRedashClient } from "./redashClient.js";
import { createServer } from "./index.js";
import { logger } from "./logger.js";
import { RedashOAuthProvider, getRedashApiKeyFromAuth } from "./auth.js";

const app = express();
app.use(express.json());

const PORT = parseInt(process.env.PORT || "3000", 10);
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// --- Legacy auth (Claude Code with headers) ---

const AUTH_TOKENS = (process.env.MCP_AUTH_TOKENS || "")
  .split(",")
  .map((t) => t.trim())
  .filter(Boolean);

// --- OAuth auth (Claude Desktop Connectors) ---

const oauthProvider = new RedashOAuthProvider();

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

// Handle the OAuth authorization form submission
app.use("/authorize/submit", express.urlencoded({ extended: false }));
app.post(
  "/authorize/submit",
  (req: express.Request, res: express.Response) => {
    const { client_id, redirect_uri, code_challenge, state, api_key } =
      req.body;
    if (!client_id || !redirect_uri || !code_challenge || !api_key) {
      res.status(400).send("Missing required fields");
      return;
    }
    oauthProvider.handleAuthorizeSubmit(
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
  if (authHeader?.startsWith("Bearer ") && AUTH_TOKENS.length > 0) {
    const token = authHeader.slice(7);
    if (AUTH_TOKENS.includes(token)) {
      const apiKey = req.headers["x-redash-api-key"] as string | undefined;
      if (!apiKey) {
        res.status(400).json({ error: "Missing X-Redash-API-Key header" });
        return;
      }
      (req as any).redashApiKey = apiKey;
      next();
      return;
    }
  }

  // Fall through to OAuth bearer auth.
  // If no token or unknown token, the SDK middleware handles 401 with
  // proper WWW-Authenticate headers to trigger the OAuth discovery flow.
  oauthBearerAuth(req, res, (err?: any) => {
    if (err) {
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
      res.status(401).json({ error: "Could not extract Redash API key from token" });
    }
  });
}

// --- Routes ---

// Health check (public)
app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

// MCP endpoint — stateless: each POST creates a fresh server + transport
app.post("/mcp", combinedAuth, async (req, res) => {
  const redashApiKey = (req as any).redashApiKey as string;

  try {
    const redashClient = createRedashClient(redashApiKey);
    const server = createServer(redashClient);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // stateless
    });

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
    await server.close();
  } catch (error) {
    logger.error(
      `MCP request error: ${error instanceof Error ? error.message : String(error)}`
    );
    if (!res.headersSent) {
      res.status(500).json({ error: "Internal server error" });
    }
  }
});

// Reject GET/DELETE on /mcp
app.all("/mcp", (_req, res) => {
  res.status(405).json({ error: "Method not allowed. Use POST." });
});

app.listen(PORT, () => {
  logger.info(`HTTP MCP server listening on port ${PORT}`);
  logger.info(`Base URL: ${BASE_URL}`);
  logger.info(
    AUTH_TOKENS.length > 0
      ? `Legacy bearer auth enabled (${AUTH_TOKENS.length} token(s))`
      : "Legacy bearer auth disabled (no MCP_AUTH_TOKENS set)"
  );
  logger.info("OAuth 2.1 auth enabled for Claude Desktop Connectors");
});
