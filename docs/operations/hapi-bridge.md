# HAPI Bridge Sidecar Integration

This guide describes an indirect integration pattern: run a HAPI bridge as an external MCP sidecar and let MicroClaw consume it through MCP tools.

## Why this pattern

- No deep embedding into `agent_engine`.
- Bridge lifecycle and failure domain stay outside MicroClaw core.
- Easy replacement: switch to another sidecar without changing core runtime logic.

## Prerequisites

1. HAPI bridge service exposes a streamable HTTP MCP endpoint, for example:
   - `http://127.0.0.1:3010/mcp`
2. MicroClaw can reach the endpoint.

## Setup

1. Create MCP fragment directory:

```sh
mkdir -p <data_dir>/mcp.d
```

2. Copy template:

```sh
cp mcp.hapi-bridge.example.json <data_dir>/mcp.d/hapi-bridge.json
```

3. Adjust endpoint/limits in `<data_dir>/mcp.d/hapi-bridge.json`.

4. Start bridge first, then start MicroClaw:

```sh
microclaw start
```

## Verify

1. Run doctor:

```sh
microclaw doctor
```

2. Check startup logs include MCP connected lines for `hapi_bridge`.

3. Ask the agent to call one tool exposed by the bridge and confirm tool result is returned.

## Troubleshooting

- Connection refused:
  - Check bridge process, endpoint host/port, firewall.
- Timeout:
  - Increase `request_timeout_secs` in fragment.
- Rate/bulkhead rejections:
  - Tune `maxConcurrentRequests`, `queueWaitMs`, `rateLimitPerMinute`.
