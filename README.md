# Redash MCP Server

Model Context Protocol (MCP) server for integrating Redash with AI assistants like Claude.

<a href="https://glama.ai/mcp/servers/j9bl90s3tw">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/j9bl90s3tw/badge" alt="Redash Server MCP server" />
</a>

> **Fork note:** This fork extends [`@suthio/redash-mcp`](https://github.com/suthio/redash-mcp) with a stateless HTTP transport and OAuth 2.1 support, intended for running a centrally deployed MCP server that multiple users can connect to. For individual use, install the upstream package directly — this fork is only needed when running a shared multi-user server.

## Features

- Connect to Redash instances via the Redash API
- List available queries and dashboards as resources
- Execute queries and retrieve results
- Create and manage queries (create, update, archive)
- List data sources for query creation
- Get dashboard details and visualizations

## Prerequisites

- Node.js (v18 or later)
- npm or yarn
- Access to a Redash instance
- Redash API key

## Environment Variables

The server requires the following environment variables:

- `REDASH_URL`: Your Redash instance URL (e.g., https://redash.example.com)
- `REDASH_API_KEY`: Your Redash API key

Optional variables:
- `REDASH_TIMEOUT`: Timeout for API requests in milliseconds (default: 30000)
- `REDASH_MAX_RESULTS`: Maximum number of results to return (default: 1000)
- `REDASH_EXTRA_HEADERS`: Extra HTTP headers to include with every Redash request. Accepts either a JSON object string or a semicolon/comma-separated list of `key=value` pairs.
- `REDASH_SOCKS_PROXY`: SOCKS proxy URL for routing requests through a proxy (e.g., `socks5h://localhost:1080`). Use `socks5h://` (with `h`) to delegate DNS resolution to the proxy, which is required for internal hostnames that don't resolve on the local machine.

Examples:

JSON (recommended):
```
REDASH_EXTRA_HEADERS='{"CF-Access-Client-Id":"<client_id>","CF-Access-Client-Secret":"<client_secret>"}'
```

Key/value list:
```
REDASH_EXTRA_HEADERS=CF-Access-Client-Id=<client_id>;CF-Access-Client-Secret=<client_secret>
```

Notes:
- The `Authorization` header is managed by the server (`Key <REDASH_API_KEY>`) and cannot be overridden.
- All extra headers are added to every request made to Redash.

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/suthio/redash-mcp.git
   cd redash-mcp
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Create a `.env` file with your Redash configuration:
   ```
   REDASH_URL=https://your-redash-instance.com
   REDASH_API_KEY=your_api_key
   # Optional: Cloudflare Access (or other gateway) headers
   # REDASH_EXTRA_HEADERS='{"CF-Access-Client-Id":"<client_id>","CF-Access-Client-Secret":"<client_secret>"}'
   ```

4. Build the project:
   ```bash
   npm run build
   ```

5. Start the server:
   ```bash
   npm start
   ```

## Usage with Claude for Desktop

To use this MCP server with Claude for Desktop, configure it in your Claude for Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

Add the following configuration (edit paths as needed):

```json
{
  "mcpServers": {
    "redash": {
      "command": "npx",
      "args": [
         "-y",
         "@suthio/redash-mcp"
      ],
      "env": {
        "REDASH_API_KEY": "your-api-key",
        "REDASH_URL": "https://your-redash-instance.com"
      }
    }
  }
}
```

## HTTP Transport (shared deployment)

In addition to stdio, this fork ships an HTTP entry point (`dist/httpServer.js`) designed to run as a long-lived server. The transport is stateless — each incoming MCP request spins up a fresh server instance, so any replica can serve any request. OAuth and bearer-token state is kept in Redis.

Run with:

```bash
node dist/httpServer.js
```

### Endpoints

- `POST /mcp` — MCP protocol endpoint. Requires authentication.
- `GET /health` — Liveness/readiness probe. Reports Redis connectivity.
- `GET /.well-known/oauth-authorization-server`, `POST /register`, `GET /authorize`, `POST /token`, `POST /revoke` — OAuth 2.1 discovery and flow, provided by the MCP SDK.

### Authentication

Two modes are supported on `POST /mcp`:

- **OAuth 2.1** (Claude Desktop Connectors): clients register via Dynamic Client Registration, the user enters their Redash API key in the `/authorize` form, and the server mints a bearer token bound to that key. Refresh tokens rotate on each use.
- **Legacy bearer + header** (Claude Code and similar): set `MCP_AUTH_TOKENS` to a comma-separated list of shared secrets. Clients send `Authorization: Bearer <token>` together with the per-user `X-Redash-API-Key` header.

### Environment variables

HTTP server:

- `PORT` — HTTP listen port (default `3000`)
- `BASE_URL` — Public URL of the server, used as the OAuth issuer and resource URL (default `http://localhost:${PORT}`)
- `TRUST_PROXY` — Value passed to Express `trust proxy` (default `1`, suitable for a single reverse proxy)

Redis (required for HTTP mode):

- `REDIS_URL` — Connection string (default `redis://localhost:6379/0`)
- `MCP_ENCRYPTION_KEY` — Key used to encrypt Redash API keys at rest in Redis (AES-256-GCM). Accepts a 64-char hex string as a raw 256-bit key, or any other string which is derived into one. If unset, API keys are stored in plaintext and the server logs a warning.

OAuth:

- `OAUTH_ALLOWED_REDIRECT_HOSTS` — Comma-separated list of additional hosts permitted as client redirect URIs. By default only loopback (`localhost`, `127.0.0.1`, `::1`) is allowed.
- `OAUTH_BASIC_AUTH_USER` / `OAUTH_BASIC_AUTH_PASS` — When both are set, the `/authorize` page is gated with HTTP Basic Auth before the API key form is shown. Recommended for public deployments.

Legacy auth (optional):

- `MCP_AUTH_TOKENS` — Comma-separated bearer tokens accepted alongside the `X-Redash-API-Key` header.

## Available Tools

### Query Management
- `list-queries`: List all available queries in Redash
- `get-query`: Get details of a specific query 
- `create-query`: Create a new query in Redash
- `update-query`: Update an existing query in Redash
- `archive-query`: Archive (soft-delete) a query
- `list-data-sources`: List all available data sources

### Query Execution
- `execute-query`: Execute a query and return results
- `execute-adhoc-query`: Execute an ad-hoc query without saving it to Redash
- `get-query-results-csv`: Get query results in CSV format (supports optional refresh for latest data)

### Dashboard Management
- `list-dashboards`: List all available dashboards
- `get-dashboard`: Get dashboard details and visualizations 
- `get-visualization`: Get details of a specific visualization

### Visualization Management
- `create-visualization`: Create a new visualization for a query
- `update-visualization`: Update an existing visualization
- `delete-visualization`: Delete a visualization

## Development

Run in development mode:
```bash
npm run dev
```

## Testing

### Unit Tests

```bash
npm test
```

### E2E Tests

```bash
npm run e2e:test
```

E2E tests use these default values (can be overridden with environment variables):
- `REDASH_URL`: https://demo.redash.io
- `REDASH_API_KEY`: test_api_key

Override example:
```bash
REDASH_URL=https://your-instance.com REDASH_API_KEY=your_key npm run e2e:test
```

### Manual Testing

```bash
npm run inspector
```

## Version History

- v1.1.0: Added query management functionality (create, update, archive)
- v1.0.0: Initial release

## License

MIT
