import express from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createRedashClient } from "./redashClient.js";
import { createServer } from "./index.js";
import { logger } from "./logger.js";

const app = express();
app.use(express.json());

const PORT = parseInt(process.env.PORT || "3000", 10);

// Comma-separated list of valid bearer tokens for service-level auth
const AUTH_TOKENS = (process.env.MCP_AUTH_TOKENS || "")
  .split(",")
  .map((t) => t.trim())
  .filter(Boolean);

function authenticateBearer(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): void {
  if (AUTH_TOKENS.length === 0) {
    next();
    return;
  }

  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    res.status(401).json({ error: "Missing or invalid Authorization header" });
    return;
  }

  const token = authHeader.slice(7);
  if (!AUTH_TOKENS.includes(token)) {
    res.status(403).json({ error: "Invalid bearer token" });
    return;
  }

  next();
}

// Health check
app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

// MCP endpoint — stateless: each POST creates a fresh server + transport
app.post("/mcp", authenticateBearer, async (req, res) => {
  const redashApiKey = req.headers["x-redash-api-key"] as string | undefined;

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
});
