# Feature Completion PR Plan (Phase 0-5)

Last Updated: 2026-02-19
Owner: microclaw core team

## Program Rules

- Every PR must include:
  - scope statement
  - DoD checklist
  - acceptance tests
  - lint/build checks
  - rollback note
- Merge order follows dependency graph below.
- No PR merges without passing required checks.

## Required CI/Lint Gate Per PR

- `cargo test -q`
- `npm --prefix web run build`
- `npm --prefix website run build`
- `node scripts/generate_docs_artifacts.mjs --check`

## Milestones

- M0: RFC freeze + tracking board (Phase 0)
- M1: Auth model live (Phase 1)
- M2: Hooks MVP live (Phase 2)
- M3: Session fork API live (Phase 3)
- M4: Metrics APIs + history live (Phase 4)
- M5: Hardening + RC release (Phase 5)

## PR Breakdown

## Phase 0: Baseline and RFC Freeze

### PR-000: Program Skeleton

- Scope: add RFC index + roadmap docs + tracking board
- DoD:
  - `docs/rfcs/*.md` exists
  - `docs/roadmap/*` exists
- Acceptance:
  - doc links valid
- Depends on: none

### PR-001: Implementation Decomposition

- Scope: split milestones into PR graph with dependencies
- DoD:
  - every phase mapped to PR ids
  - each PR has DoD + acceptance + rollback
- Acceptance:
  - no unmapped requirement from Phase 0-5 list
- Depends on: PR-000

## Phase 1: Auth and Authorization

### PR-100: Auth DB Migration

- Scope: create auth/session/api key tables and indexes
- DoD:
  - idempotent migrations
  - storage helpers
- Acceptance:
  - migration tests pass from empty and legacy DB
- Depends on: PR-001

### PR-101: Password Login + Session Cookie

- Scope: add login/logout/status APIs and session issuance
- DoD:
  - password verify + session create/revoke
  - secure cookie settings
- Acceptance:
  - integration tests for login success/failure and logout
- Depends on: PR-100

### PR-102: API Keys with Scopes

- Scope: create/list/revoke API keys and scope checks
- DoD:
  - hashed key storage
  - one-time secret display
  - scope enforcement utility
- Acceptance:
  - unit tests for scope matrix
- Depends on: PR-100

### PR-103: Auth Middleware + Endpoint Scope Map

- Scope: centralized auth gate and route-to-scope mapping
- DoD:
  - read/write/admin/approvals endpoint mapping
  - legacy token fallback flag
- Acceptance:
  - endpoint auth integration tests
- Depends on: PR-101, PR-102

### PR-104: Rate Limiting Baseline

- Scope: per-ip throttle for login and sensitive APIs
- DoD:
  - configurable thresholds and retry hints
- Acceptance:
  - throttle tests with 429 + retry behavior
- Depends on: PR-103

### PR-105: Auth Docs + Upgrade Notes

- Scope: auth configuration and migration docs
- DoD:
  - config defaults documented
  - upgrade path documented
- Acceptance:
  - docs build and link checks pass
- Depends on: PR-104

## Phase 2: Hooks Platform MVP

### PR-200: Hook Spec + Parser

- Scope: `HOOK.md` schema and parser/validator
- DoD:
  - parse name/events/command/requires
- Acceptance:
  - parser unit tests
- Depends on: PR-001

### PR-201: Hook Discovery + Eligibility

- Scope: workspace/user hook discovery and requirements checks
- DoD:
  - precedence rules and ineligible reporting
- Acceptance:
  - discovery tests with mixed valid/invalid hooks
- Depends on: PR-200

### PR-202: Hook Runtime Executor

- Scope: execute hooks with timeout and output caps
- DoD:
  - allow/block/modify result handling
- Acceptance:
  - runtime tests for each outcome
- Depends on: PR-201

### PR-203: Agent Event Wiring (3 Events)

- Scope: wire `BeforeLLMCall`, `BeforeToolCall`, `AfterToolCall`
- DoD:
  - payload shapes and mutation constraints enforced
- Acceptance:
  - end-to-end hook integration tests
- Depends on: PR-202

### PR-204: Hooks CLI

- Scope: `hooks list/info/enable/disable`
- DoD:
  - command help and JSON output modes
- Acceptance:
  - CLI snapshot tests
- Depends on: PR-201

### PR-205: Sample Hooks + Docs

- Scope: minimal built-in examples and docs
- DoD:
  - 2 examples: logger + high-risk blocker
- Acceptance:
  - e2e test with sample blocker hook
- Depends on: PR-203, PR-204

## Phase 3: Session Fork

### PR-300: Session Schema Migration

- Scope: add `parent_session_key` and `fork_point`
- DoD:
  - migration + index + storage model updates
- Acceptance:
  - DB migration tests
- Depends on: PR-001

### PR-301: Fork Service Logic

- Scope: transcript copy and inherited session settings
- DoD:
  - support full copy and fork-point copy
- Acceptance:
  - service unit tests for boundaries
- Depends on: PR-300

### PR-302: `sessions.fork` API

- Scope: add API endpoint and request/response contracts
- DoD:
  - auth scope mapping: `operator.write`
- Acceptance:
  - API integration tests
- Depends on: PR-301, PR-103

### PR-303: Session Tree Query + Delete Rules

- Scope: parent-child query helpers and non-cascade delete behavior
- DoD:
  - delete parent retains children as roots
- Acceptance:
  - delete behavior integration tests
- Depends on: PR-300

### PR-304: Docs + Compatibility Notes

- Scope: API docs and migration compatibility notes
- DoD:
  - explicit legacy behavior statement
- Acceptance:
  - docs checks pass
- Depends on: PR-302, PR-303

## Phase 4: Metrics and Tracing

### PR-400: Metrics Registry Foundation

- Scope: define core metric names/types/labels
- DoD:
  - HTTP/LLM/Tool/MCP/Session metrics registered
- Acceptance:
  - unit tests for naming and labels
- Depends on: PR-001

### PR-401: Metrics Instrumentation in Runtime

- Scope: instrument web/agent/tools/mcp/session paths
- DoD:
  - counters and histograms emitted
- Acceptance:
  - integration tests with non-zero metrics
- Depends on: PR-400

### PR-402: Metrics History Storage (SQLite)

- Scope: periodic snapshot persistence + retention cleanup
- DoD:
  - `metrics_history` table and cleanup job
- Acceptance:
  - retention tests
- Depends on: PR-400

### PR-403: Metrics APIs

- Scope: `/api/metrics`, `/api/metrics/summary`, `/api/metrics/history`
- DoD:
  - response schemas documented and tested
- Acceptance:
  - API integration tests
- Depends on: PR-401, PR-402

### PR-404: Metrics API Hardening

- Scope: payload stability and retention policy hardening
- DoD:
  - API schema locked
  - retention behavior covered by tests
- Acceptance:
  - metrics API contract tests pass
- Depends on: PR-401

### PR-405: Observability Docs + Grafana Starter

- Scope: docs + sample dashboard JSON
- DoD:
  - panel mapping for core metrics
- Acceptance:
  - dashboard JSON linted/validated
- Depends on: PR-403, PR-404

## Phase 5: Hardening and Release Candidate

### PR-500: Security Regression Pack

- Scope: auth bypass, scope bypass, hook abuse regressions
- DoD:
  - security regression suite in CI
- Acceptance:
  - negative tests all pass
- Depends on: M1, M2, M3, M4

### PR-501: Performance Regression Pack

- Scope: baseline throughput/latency tests for key routes and agent loop
- DoD:
  - repeatable benchmark harness committed
- Acceptance:
  - benchmark report generated in CI artifact
- Depends on: M4

### PR-502: Migration Regression Pack

- Scope: legacy DB/config upgrade path tests
- DoD:
  - migrations tested across representative legacy fixtures
- Acceptance:
  - all fixtures migrate cleanly
- Depends on: M1, M3, M4

### PR-503: Operational Docs Completion

- Scope: configuration, operations, security, troubleshooting
- DoD:
  - runbooks for auth/hooks/metrics/fork failures
- Acceptance:
  - docs review checklist complete
- Depends on: PR-500, PR-502

### PR-504: Release Candidate + Upgrade Guide

- Scope: RC tagging checklist and upgrade guide
- DoD:
  - release checklist complete
  - rollback instructions validated
- Acceptance:
  - dry-run release completed in staging
- Depends on: PR-503

## Dependency Graph Summary

- M1 depends on PR-100..105
- M2 depends on PR-200..205
- M3 depends on PR-300..304
- M4 depends on PR-400..405
- M5 depends on PR-500..504

## Definition of Done (Program-Level)

- All PR DoDs checked
- Required CI/lint gate green on each PR
- No open critical regressions in security/perf/migration packs
- RC guide validated in staging
