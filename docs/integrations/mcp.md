# MCP Integration

MicroClaw can load Model Context Protocol servers without adding provider- or channel-specific code. MCP tools enter the same registry, authorization, hook, and audit path as built-in tools.

## Configuration files

The runtime reads:

- `<data_dir>/mcp.json` for the main configuration
- `<data_dir>/mcp.d/*.json` for optional fragments

Start with the local-only example:

```sh
cp mcp.minimal.example.json <data_dir>/mcp.json
```

Use the full example when remote transport is required:

```sh
cp mcp.example.json <data_dir>/mcp.json
```

Fragments keep integrations independent:

```sh
mkdir -p <data_dir>/mcp.d
cp mcp.peekaboo.example.json <data_dir>/mcp.d/peekaboo.json
```

## Supported transports

- `stdio`
- `streamable_http`

The default protocol version is `2025-11-05` and can be overridden globally or per server. SSE-only servers require a protocol bridge.

Minimal example:

```json
{
  "defaultProtocolVersion": "2025-11-05",
  "mcpServers": {
    "filesystem": {
      "transport": "stdio",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "."]
    },
    "remote": {
      "transport": "streamable_http",
      "endpoint": "http://127.0.0.1:8080/mcp"
    }
  }
}
```

Run `microclaw doctor` after editing MCP configuration. It checks configured command dependencies. Startup logs report whether each server connected and which protocol was negotiated.

## Trust tiers

Each server can carry a named trust tier that maps onto tool-policy risk for
every tool it exposes:

```json
{
  "mcpServers": {
    "filesystem": {"command": "npx", "args": ["..."], "trust": "trusted"},
    "marketplace-thing": {"command": "npx", "args": ["..."], "trust": "sandboxed"}
  }
}
```

- `trusted` → tools rate **low** risk (pass a `max_risk: low` policy).
- `limited` (default) → **medium**, the historical uniform rating for all MCP
  tools; omitting the field changes nothing.
- `sandboxed` → **high**: a `max_risk: medium` policy blocks the server's
  tools, and calls from web/control chats require the explicit high-risk
  approval flow before running.

Tiers feed the same policy and approval choke points as built-in tools; they
can raise scrutiny for a server you don't fully trust, and lower the *rating*
for one you do — they never bypass deny lists or grants.

## Security model

An MCP server is executable code or a remote capability boundary. Before enabling one:

1. Review the package, command, arguments, environment variables, and network destination.
2. Grant the smallest filesystem and network scope it needs.
3. Avoid forwarding broad credential environments.
4. Apply shared tool grants and egress policy where appropriate — and set a
   `trust` tier (above) for any server you wouldn't hand a shell.
5. Prefer pinned package versions in production rather than `latest`.

See the [execution model](../security/execution-model.md) and [secure runtime](../security/secure-runtime.md).

## Browser automation

Playwright MCP can connect through its browser extension when access to an existing signed-in Chrome session is required. Add an isolated fragment under `<data_dir>/mcp.d/` and provide the extension token only to that server.

```json
{
  "mcpServers": {
    "playwright": {
      "transport": "stdio",
      "command": "npx",
      "args": ["-y", "@playwright/mcp@latest", "--extension"],
      "env": {
        "PLAYWRIGHT_MCP_EXTENSION_TOKEN": "<token>"
      }
    }
  }
}
```

For production, replace `latest` with a reviewed version. Browser automation acts with the permissions of the connected browser profile, including its signed-in sessions.

## Desktop and sidecar examples

- macOS desktop automation: [`mcp.peekaboo.example.json`](../../mcp.peekaboo.example.json)
- Windows desktop automation: [`mcp.windows.desktop.example.json`](../../mcp.windows.desktop.example.json)
- HAPI sidecar operations: [HAPI bridge](../operations/hapi-bridge.md)
- Weixin native integration: [Weixin](../operations/weixin.md)

The ongoing SDK evaluation is documented in [MCP SDK evaluation](../mcp-sdk-evaluation.md).
