# Operations Runbook

## Auth Issues

- Symptom: `401 unauthorized`
  - Check `Authorization: Bearer <api-key-or-legacy-token>` or `mc_session` cookie.
  - Verify key scopes via `GET /api/auth/api_keys`.
- Symptom: unsure whether deployment config is safe
  - Run `GET /api/config/self_check` and inspect `risk_level` + `warnings`.
  - Fix high-severity items first (`severity: high`).

- Symptom: login throttled
  - Login endpoint rate-limits repeated attempts per client key.
  - Wait for cooldown window and retry.

## Hook Issues

- List hooks: `microclaw hooks list`
- Inspect hook: `microclaw hooks info <name>`
- Disable bad hook quickly: `microclaw hooks disable <name>`

If a hook times out or crashes, runtime skips the hook and continues.

## Session Fork Issues

- Inspect tree: `GET /api/sessions/tree`
- Create branch: `POST /api/sessions/fork`
- Deleting parent session does not cascade to children.

## ACP Subagent Runtime

- Symptom: `sessions_spawn(runtime="acp")` returns `ACP runtime is disabled`
  - Set `subagents.acp.enabled: true`
  - Set `subagents.acp.command` to an ACP-compatible agent executable, or add at least one enabled target under `subagents.acp.targets`

- Symptom: ACP run is accepted but later fails quickly
  - Verify the selected ACP command starts and speaks ACP over stdio
  - Check `subagents_log` for the run and inspect stderr included in the failure
  - Confirm the chat working directory contains the repo/context the external agent expects

- Symptom: `sessions_spawn(runtime="acp")` returns unknown target or multiple target errors
  - Pass `runtime_target` when using named ACP workers
  - Or set `subagents.acp.default_target` so plain `runtime="acp"` has a stable default
  - Verify target names under `subagents.acp.targets`

- Operational notes:
  - ACP-backed subagents reuse the normal `subagent_runs` lifecycle and announce path
  - ACP file and terminal operations are scoped to the chat working directory
  - `subagents_log` now records ACP permission, plan, tool-call, file, and terminal events
  - ACP permission requests are still operator-configurable and may be auto-approved, so keep the feature operator-controlled

## Gateway Bridge Issues

- Symptom: Mission Control / OpenClaw operator cannot connect
  - The compatibility bridge is served from `GET /` with WebSocket upgrade, not `/ws`.
  - Verify the web listener first: `GET /api/health`.
  - Check service state: `microclaw gateway status --json --deep`

- Symptom: local gateway RPC returns unauthorized
  - Export one of `MICROCLAW_GATEWAY_TOKEN`, `OPENCLAW_GATEWAY_TOKEN`, `GATEWAY_TOKEN`, or `MICROCLAW_API_KEY`.
  - WebSocket `connect` requires a valid operator token; mutating RPC methods require `operator.write`.

- Quick smoke checks:

```sh
MICROCLAW_GATEWAY_TOKEN=... microclaw gateway call health
MICROCLAW_GATEWAY_TOKEN=... microclaw gateway call status
MICROCLAW_GATEWAY_TOKEN=... microclaw gateway call sessions_send \
  --params '{"sessionKey":"main","message":"status summary"}'
```

- Supported bridge methods:
  - `health`, `status`, `chat.send`, `chat.history`
  - `session_delete`, `sessions_send`, `sessions_kill`, `sessions_spawn`
  - `session_setThinking`, `session_setVerbose`, `session_setReasoning`, `session_setLabel`
  - `agents.list`, `models.list`, `config.get`, `node.list`

- Session-control notes:
  - `sessions_send` emits live `chat` events and a terminal `final` state for normal messages.
  - `sessions_spawn` can create a new session and persist an initial label.
  - `session_set*` writes only the provided field and preserves the rest of the stored session settings.
  - Session labels and settings are persisted in the `sessions` table and flow back into session listings / bridge payloads.
  - `sessions_send` control payloads are acknowledged today, but not yet enforced as runtime controls.

- Symptom: logs show send failures after operator disconnect
  - Messages such as `sending after closing is not allowed`, `already closed`, or `connection closed normally` are downgraded as expected closed-socket noise.

## Metrics Issues

- Check snapshot: `GET /api/metrics`
- Check history: `GET /api/metrics/history?minutes=60`
- If OTLP is enabled, verify `channels.observability.otlp_endpoint` is reachable.
- If points are missing under burst traffic, raise `otlp_queue_capacity` and review retry settings.

If history is empty, generate traffic first and re-check.

MCP reliability counters (snapshot/summary):
- `mcp_rate_limited_rejections`
- `mcp_bulkhead_rejections`
- `mcp_circuit_open_rejections`

These counters are also persisted to `metrics_history` and available in
`GET /api/metrics/history`.

## Stability Gate

- Run stability smoke suite locally: `scripts/ci/stability_smoke.sh`
- CI gate: `Stability Smoke` job in `.github/workflows/ci.yml`
- Scope:
  - cross-chat permissions
  - scheduler restart persistence
  - sandbox fallback and require-runtime fail-closed behavior
  - web inflight and rate-limit regression

## SLO Alerts

- Query SLO summary: `GET /api/metrics/summary`
- Request success burn alert: `slo.request_success_rate.value < 0.99`
- Latency burn alert: `slo.e2e_latency_p95_ms.value > 10000`
- Tool reliability burn alert: `slo.tool_reliability.value < 0.97`
- Scheduler recoverability alert: `slo.scheduler_recoverability_7d.value < 0.999`

When any burn alert is active:
- freeze non-critical feature merges
- triage and assign incident owner
- if user-facing impact continues, prepare rollback/hotfix path per stability plan

## Scheduler DLQ Replay

- Inspect failed scheduler runs: use tool `list_scheduled_task_dlq` with `chat_id`
- Replay pending failures: use tool `replay_scheduled_task_dlq` with `chat_id`
- Optional filters:
  - `task_id` to target one task
  - `limit` to bound replay batch size
- Replay behavior:
  - re-queues task with immediate `next_run`
  - marks DLQ entry as replayed with a replay note (`queued` or `skipped` reason)

## Timeout Budget Tuning

- Global tool timeout default: `default_tool_timeout_secs`
- Per-tool timeout overrides: `tool_timeout_overrides.<tool_name>`
- Global MCP request timeout default: `default_mcp_request_timeout_secs`
- MCP per-server override remains supported in `mcp.json` and `mcp.d/*.json`:
  - `mcpServers.<name>.request_timeout_secs`

Precedence:
- Tools: input `timeout_secs` > `tool_timeout_overrides` > `default_tool_timeout_secs`
- MCP: server `request_timeout_secs` > `default_mcp_request_timeout_secs`

Example config:

```yaml
default_tool_timeout_secs: 30
tool_timeout_overrides:
  bash: 90
  browser: 45
  web_fetch: 20
  web_search: 20
default_mcp_request_timeout_secs: 120
```

## Web Fetch Validation

`web_fetch` now has two independent validation layers:

- content validation (`web_fetch_validation`) to detect prompt-injection patterns in fetched text
- URL policy validation (`web_fetch_url_validation`) to enforce scheme/host rules before fetch

Recommended baseline:

```yaml
web_fetch_validation:
  enabled: true
  strict_mode: true
  max_scan_bytes: 100000

web_fetch_url_validation:
  enabled: true
  allowed_schemes: ["https", "http"]
  allowlist_hosts: []
  denylist_hosts:
    - "localhost"
    - "127.0.0.1"
    - "169.254.169.254"
```

### Feed Sync (Optional)

`web_fetch_url_validation.feed_sync` can pull host entries from remote feeds and merge them into
runtime allowlist/denylist sets.

Example:

```yaml
web_fetch_url_validation:
  enabled: true
  allowed_schemes: ["https", "http"]
  allowlist_hosts: []
  denylist_hosts: []
  feed_sync:
    enabled: true
    fail_open: true
    max_entries_per_source: 10000
    sources:
      - enabled: true
        mode: denylist
        url: "https://example.com/blocked-hosts.txt"
        format: lines
        refresh_interval_secs: 3600
        timeout_secs: 10
      - enabled: true
        mode: allowlist
        url: "https://example.com/approved-hosts.csv"
        format: csv_first_column
        refresh_interval_secs: 3600
        timeout_secs: 10
```

Operational notes:

- URL checks run before network fetch; denylist takes precedence over allowlist.
- If `allowlist_hosts` is non-empty, target host must match allowlist.
- `fail_open: true` skips an unavailable feed; `fail_open: false` blocks requests when feed fetch fails.
- Feed data is cached in memory and refreshed per-source `refresh_interval_secs`.

## MCP Reliability Tuning

- `mcp.json` / `mcp.d/*.json` support per-server circuit breaker knobs:
  - `circuit_breaker_failure_threshold` (default `5`)
  - `circuit_breaker_cooldown_secs` (default `30`)
- `request_timeout_secs` remains per-server timeout budget.

## MCP Server Guardrails

- `mcp.json` / `mcp.d/*.json` support server-level isolation controls:
  - `max_concurrent_requests` (default `4`)
  - `queue_wait_ms` (default `200`)
  - `rate_limit_per_minute` (default `120`)

Example:

```json
{
  "mcpServers": {
    "remote": {
      "transport": "streamable_http",
      "endpoint": "http://127.0.0.1:8080/mcp",
      "request_timeout_secs": 120,
      "circuit_breaker_failure_threshold": 5,
      "circuit_breaker_cooldown_secs": 30,
      "max_concurrent_requests": 4,
      "queue_wait_ms": 200,
      "rate_limit_per_minute": 120
    }
  }
}
```

Behavior:
- consecutive MCP request failures trip the breaker and short-circuit calls during cooldown.
- after cooldown, requests are attempted again automatically.
- requests are fail-fast when queue wait budget is exceeded.
- per-server rate limit enforces a fixed 60s window budget.

## Sidecar MCP Integration (HAPI Bridge)

Use this pattern when you want remote terminal/session capability via an external bridge, without embedding terminal runtime logic into MicroClaw core.

1. Keep base MCP config in `<data_dir>/mcp.json` (optional).
2. Add sidecar config as a fragment in `<data_dir>/mcp.d/hapi-bridge.json`.
3. Start the bridge service separately, then start MicroClaw.

Example fragment:

```json
{
  "mcpServers": {
    "hapi_bridge": {
      "transport": "streamable_http",
      "endpoint": "http://127.0.0.1:3010/mcp",
      "request_timeout_secs": 180
    }
  }
}
```

Reference template: repository file `mcp.hapi-bridge.example.json`.
Step-by-step guide: `docs/operations/hapi-bridge.md`.

## Memory MCP Backend (Optional)

If any configured MCP server exposes both `memory_query` and `memory_upsert`, MicroClaw enables MCP-first structured-memory operations:

- prompt-time structured-memory reads/searches
- explicit `remember ...` fast path writes
- reflector insert/update/supersede/touch flows
- structured memory tool operations (`structured_memory_search/update/delete`)

Fallback policy:

- on MCP call failure, timeout, or invalid/unknown response shape, MicroClaw falls back to built-in SQLite memory automatically
- fallback is per operation (best-effort), so one MCP failure does not disable memory for the whole runtime
- fallback reasons are classified and surfaced as stable categories in health state, for example `timeout`, `transport`, `invalid_payload`, or `unsupported_operation`

Operational checks:

- confirm startup logs include `Memory MCP backend enabled via server '<name>'`
- confirm startup health probe does not log `memory MCP startup probe failed`; if it does, MicroClaw keeps the external provider attached but serves operations via SQLite fallback as needed
- verify server tool list includes exact names `memory_query` and `memory_upsert`
- inspect `/api/health` or config self-check output for `memory_backend` health:
  - `startup_probe_ok=false` means the provider was discovered but failed the initial `memory_query(list)` probe
  - high `consecutive_primary_failures` or `total_fallbacks` means the runtime is degrading to SQLite frequently
  - `last_fallback_reason` records the most recent classified fallback reason
- if semantic retrieval quality drops while MCP is enabled, note that local `sqlite-vec` KNN ranking is skipped for MCP-backed rows

Consistency model:

- fallback is evaluated per operation, not per runtime: a failed MCP read/write can fall back to SQLite even while later operations retry the external provider
- this prioritizes availability over strict cross-store consistency; short-lived divergence between SQLite and the external memory store is therefore possible
- explicit memory reads/writes and tool calls continue through SQLite fallback when the external provider is unhealthy
- background reflector writes are paused when startup probe fails or repeated primary-provider failures indicate the external provider is unhealthy; this limits silent divergence from bulk background writes
- after the external provider recovers, new operations go back to MCP-first behavior, but data written only through SQLite fallback is not automatically backfilled into the external store

Minimal MCP config example (memory MCP server + local filesystem):

```json
{
  "defaultProtocolVersion": "2024-11-05",
  "mcpServers": {
    "filesystem": {
      "transport": "stdio",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "."]
    },
    "memory": {
      "transport": "streamable_http",
      "endpoint": "http://127.0.0.1:8090/mcp",
      "headers": {
        "Authorization": "Bearer REPLACE_ME"
      },
      "request_timeout_secs": 60
    }
  }
}
```

The `memory` server must expose MCP tools named exactly `memory_query` and `memory_upsert`.
