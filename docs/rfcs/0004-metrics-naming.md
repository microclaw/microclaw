# RFC 0004: Metrics and Tracing Naming Standard

- Status: Draft
- Owner: runtime/observability
- Target Phase: Phase 4
- Last Updated: 2026-02-19

## Context

MicroClaw has usage reporting and memory observability, but lacked a standardized runtime metrics schema and time-series storage API.

## Goals

- Define stable JSON metric field names.
- Add JSON metrics APIs + persisted history in SQLite.

## Non-Goals

- Full distributed tracing backend integration in first pass.

## Metric Naming

### HTTP

- `http_requests`

### LLM

- `llm_completions`
- `llm_input_tokens`
- `llm_output_tokens`

### Tools

- `tool_executions`

### MCP

- `mcp_calls`

### Session

- `active_sessions`

## APIs

- `GET /api/metrics`
- `GET /api/metrics/summary`
- `GET /api/metrics/history`

## Persistence

SQLite table: `metrics_history`

- timestamp_ms
- counter snapshots
- gauges
- selected histogram aggregates

Retention default: 7 days.

## Testing Plan

- metric registration uniqueness
- endpoint payload schema tests
- history retention cleanup tests

## Rollback Plan

- disable metrics feature flags
- leave history table inert
