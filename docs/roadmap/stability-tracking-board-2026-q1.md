# Stability Tracking Board (2026 Q1)

## P0

1. SLO metrics contract + alert thresholds
- Owner: Platform
- Acceptance:
  - request success, e2e latency p95, tool reliability, scheduler recoverability are queryable
  - alert rules documented in runbook

2. CI stability smoke gate
- Owner: Runtime
- Acceptance:
  - dedicated CI job runs targeted reliability suite
  - job blocks merge on failure

3. Scheduler restart recoverability suite
- Owner: Runtime
- Acceptance:
  - restart integration tests cover pending tasks, paused tasks, failed tasks
  - zero regression against baseline fixtures

4. Cross-chat permission regression pack
- Owner: Runtime
- Acceptance:
  - all cross-chat tools tested for deny/allow matrix
  - explicit checks for web caller constraints

5. Sandbox fallback + require_runtime regressions
- Owner: Runtime
- Acceptance:
  - mode=off/all + runtime available/unavailable matrix covered
  - explicit assertions for fallback vs fail-closed behavior

## P1

1. Scheduler dead-letter queue + replay command
- Owner: Runtime
- Acceptance:
  - failed runs are persisted in DLQ
  - replay command supports selective retry

2. Tool/MCP timeout budget policy
- Owner: Runtime
- Acceptance:
  - default timeout budget matrix documented
  - per-tool budget override supported and tested

3. Web health posture panel enhancements
- Owner: Web
- Acceptance:
  - show SLO state snapshot, fallback counts, approval block rate
  - includes actionable remediation hints

4. Incident runbook expansion
- Owner: Platform
- Acceptance:
  - playcards for top 5 incident types
  - rollback drill steps validated

## P2

1. Load profile benchmark harness
- Owner: Platform
- Acceptance:
  - repeatable benchmark script committed
  - release compare report generated

2. Canary automation and budget check
- Owner: Platform
- Acceptance:
  - canary script records SLO deltas
  - release promotion requires budget green

## Status Legend

- `todo`
- `in_progress`
- `blocked`
- `done`
