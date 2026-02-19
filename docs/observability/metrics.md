# Metrics and Tracing Guide

## Endpoints

- `GET /api/metrics`: current counters/gauges snapshot.
- `GET /api/metrics/history?minutes=1440&limit=2000`: persisted timeline from SQLite.

## Fields

- `http_requests`
- `llm_completions`
- `llm_input_tokens`
- `llm_output_tokens`
- `tool_executions`
- `mcp_calls`
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

## OTLP Exporter

Optional OTLP/HTTP protobuf export:

```yaml
channels:
  observability:
    otlp_enabled: true
    otlp_endpoint: "http://127.0.0.1:4318/v1/metrics"
    service_name: "microclaw"
    otlp_export_interval_seconds: 15
    otlp_headers:
      Authorization: "Bearer <token>"
```
