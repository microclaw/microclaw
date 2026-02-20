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

## Metrics Issues

- Check snapshot: `GET /api/metrics`
- Check history: `GET /api/metrics/history?minutes=60`
- If OTLP is enabled, verify `channels.observability.otlp_endpoint` is reachable.
- If points are missing under burst traffic, raise `otlp_queue_capacity` and review retry settings.

If history is empty, generate traffic first and re-check.

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
- MCP per-server override remains supported in `mcp.json`:
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

## MCP Reliability Tuning

- `mcp.json` supports per-server circuit breaker knobs:
  - `circuit_breaker_failure_threshold` (default `5`)
  - `circuit_breaker_cooldown_secs` (default `30`)
- `request_timeout_secs` remains per-server timeout budget.

## MCP Server Guardrails

- `mcp.json` supports server-level isolation controls:
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
