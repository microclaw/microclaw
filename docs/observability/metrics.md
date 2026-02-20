# Metrics and Tracing Guide

## Endpoints

- `GET /api/metrics`: current counters/gauges snapshot.
- `GET /api/metrics/summary`: snapshot plus derived reliability summary.
- `GET /api/metrics/history?minutes=1440&limit=2000`: persisted timeline from SQLite.

## Fields

- `http_requests`
- `llm_completions`
- `llm_input_tokens`
- `llm_output_tokens`
- `tool_executions`
- `mcp_calls`
- `mcp_rate_limited_rejections`
- `mcp_bulkhead_rejections`
- `mcp_circuit_open_rejections`
- `active_sessions`

## Persistence

Metrics snapshots are persisted to SQLite `metrics_history` by minute bucket:

- `timestamp_ms` (primary key)
- `llm_completions`
- `llm_input_tokens`
- `llm_output_tokens`
- `http_requests`
- `tool_executions`
- `mcp_calls`
- `mcp_rate_limited_rejections`
- `mcp_bulkhead_rejections`
- `mcp_circuit_open_rejections`
- `active_sessions`

Retention can be configured via:

```yaml
channels:
  web:
    metrics_history_retention_days: 30
```

## Typical Queries

- Traffic last 24h: `/api/metrics/history?minutes=1440`
- High-load short window: `/api/metrics/history?minutes=60&limit=3600`

`/api/metrics/summary` derived fields:
- `summary.mcp_rejections_total`
- `summary.mcp_rejection_ratio`

OTLP export includes corresponding counters:
- `microclaw_mcp_rate_limited_rejections`
- `microclaw_mcp_bulkhead_rejections`
- `microclaw_mcp_circuit_open_rejections`

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
