# Stability Report

## Scope

- Auth and scoped authorization paths
- Hook execution lifecycle (BeforeLLMCall/BeforeToolCall/AfterToolCall)
- Session fork APIs and metadata handling
- Metrics APIs and persistence

## Validation Matrix

- Unit/integration test suite: `cargo test -q`
- Web UI build: `npm --prefix web run build`
- Docs site build: `npm --prefix website run build`
- Generated docs drift: `node scripts/generate_docs_artifacts.mjs --check`

## Current Status

- Rust tests pass.
- Web and docs builds pass.
- Session fork, metrics, and hooks integration tests pass.

## Regression Focus

- Auth regressions:
  - legacy token fallback
  - session cookie login/logout
  - API key scope enforcement
- Hook regressions:
  - invalid hooks skipped safely
  - block/modify behavior
  - timeout/command failure isolation
- Migration regressions:
  - schema v5/v6/v7 migration path
  - no destructive behavior on existing sessions

## Residual Risk

- Hook scripts are operator code; misconfiguration can block traffic.
- Metrics are available via JSON APIs.
- High-QPS deployments may require external scrape/retention tuning.
