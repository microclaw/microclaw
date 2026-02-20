# Metrics and Tracing Guide

## Endpoints

- `GET /api/metrics`: current counters/gauges snapshot.
- `GET /api/metrics/summary`: SLO-oriented summary contract.
- `GET /api/metrics/history?minutes=1440&limit=2000`: persisted timeline from SQLite.

## Fields

- `http_requests`
- `request_ok`
- `request_error`
- `llm_completions`
- `llm_input_tokens`
- `llm_output_tokens`
- `tool_executions`
- `tool_success`
- `tool_error`
- `tool_policy_blocks` (excluded from tool reliability denominator)
- `mcp_calls`
- `mcp_rate_limited_rejections`
- `mcp_bulkhead_rejections`
- `mcp_circuit_open_rejections`
- `active_sessions`

## SLO Contract (`/api/metrics/summary`)

`/api/metrics/summary` returns an explicit SLO block:

- `slo.request_success_rate`:
  - `value` from `request_ok / (request_ok + request_error)` over current process lifetime
  - `target: 0.995`
  - `burn_alert: 0.99`
- `slo.e2e_latency_p95_ms`:
  - `value` is runtime p95 from sampled successful request latencies
  - `target: 6000`
  - `burn_alert: 10000`
- `slo.tool_reliability`:
  - `value` from `tool_success / (tool_success + tool_error)`
  - excludes `tool_policy_blocks` (`approval_required`, `execution_policy_blocked`)
  - `target: 0.985`
  - `burn_alert: 0.97`
- `slo.scheduler_recoverability_7d`:
  - `value` from successful scheduler runs / total scheduler runs in recent 7 days
  - `target: 1.0`
  - `burn_alert: 0.999`

## Persistence

Metrics snapshots are persisted to SQLite `metrics_history` by minute bucket:

- `timestamp_ms` (primary key)
- `llm_completions`
- `llm_input_tokens`
- `llm_output_tokens`
- `http_requests`
- `tool_executions`
- `mcp_calls`
- `active_sessions`

Note:
- MCP rejection counters are currently snapshot-only fields from `GET /api/metrics` and
  `GET /api/metrics/summary` (not persisted in `metrics_history` yet).

Retention can be configured via:

```yaml
channels:
  web:
    metrics_history_retention_days: 30
```

## Typical Queries

- Traffic last 24h: `/api/metrics/history?minutes=1440`
- High-load short window: `/api/metrics/history?minutes=60&limit=3600`

## OTLP Exporter

Optional OTLP/HTTP protobuf export:

```yaml
channels:
  observability:
    otlp_enabled: true
    otlp_endpoint: "http://127.0.0.1:4318/v1/metrics"
    service_name: "microclaw"
    otlp_export_interval_seconds: 15
    otlp_queue_capacity: 256
    otlp_retry_max_attempts: 3
    otlp_retry_base_ms: 500
    otlp_retry_max_ms: 8000
    otlp_headers:
      Authorization: "Bearer <token>"
```

Retry/backoff behavior:

- exporter uses bounded async queue (`otlp_queue_capacity`)
- when queue is full, latest snapshot enqueue fails and is dropped with warning log
- each queued snapshot retries with exponential backoff
- delay progression: `otlp_retry_base_ms` -> doubled per retry -> capped by `otlp_retry_max_ms`
- max retry rounds: `otlp_retry_max_attempts`
