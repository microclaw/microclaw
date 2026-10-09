---
id: architecture-mcp
title: Architecture - MCP Integration
sidebar_position: 12
---

MCP extends tool surface area without baking all integrations into MicroClaw itself.


## Transport model

Supported transports:

- `stdio`
- `streamable_http`

Protocol version is negotiated during initialize (default currently `2024-11-05`, configurable per server/global).

Config sources are merged from:

- `<data_dir>/mcp.json`
- `<data_dir>/mcp.d/*.json` (filename order; later files override earlier definitions for the same server key)

## Reliability model

- request timeout (`request_timeout_secs`)
- retry + reconnect for stdio (`max_retries`)
- tools cache with TTL + forced refresh
- periodic health probe (`health_interval_secs`, `0` disables)

## Tool exposure

MCP tools are registered into the same runtime tool registry with namespaced identifiers.
This keeps planner behavior consistent between built-in tools and MCP tools.

Additionally, MicroClaw can use MCP as a structured-memory backend when a server exposes:

- `memory_query`
- `memory_upsert`

In that mode, memory operations become MCP-first with automatic fallback to local SQLite on per-call failures.

Minimal config sketch:

```json
{
  "mcpServers": {
    "memory": {
      "transport": "streamable_http",
      "endpoint": "http://127.0.0.1:8090/mcp"
    }
  }
}
```

This server is considered memory-capable only when it exposes both `memory_query` and `memory_upsert`.

## Operational guidance

- Start with minimal local MCP config.
- Add remote servers one-by-one.
- Monitor tool list refresh and probe failures in logs.
- Treat endpoint auth and command dependencies as first-class operational dependencies.

## Optional Parallel Search MCP

[Parallel Search MCP](https://docs.parallel.ai/integrations/mcp/search-mcp) adds
web search and page extraction without a Parallel API key. Copy the repository's
`mcp.parallel.example.json` into `<data_dir>/mcp.d/parallel.json`, then restart
MicroClaw. It uses native `streamable_http` and exposes
`mcp_parallel_web_search` and `mcp_parallel_web_fetch` with the default `limited`
trust tier. Existing web tools and other MCP servers remain available.

Search takes `objective` and `search_queries`; fetch takes `urls` and an optional
`objective`. Anonymous access has lower rate limits and is intended for
exploration and light use. Remove the fragment and restart to disable it.
