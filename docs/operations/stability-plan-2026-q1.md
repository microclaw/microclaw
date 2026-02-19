# Stability Plan (2026 Q1)

## Objective

Move MicroClaw from feature-growth mode to reliability mode with explicit service-level targets, release gates, and rollback criteria.

## Scope

- Runtime stability (agent loop, tool loop, scheduler, web API)
- Operational safety (approval/risk paths, sandbox fallback behavior)
- Recoverability (restart resilience, dead-letter + replay)
- Measurable user-facing reliability (availability + latency + error budget)

## SLOs (initial)

### SLO-1: Request Success Rate

- Definition: percentage of user requests that complete with a terminal response and no infrastructure/tool fatal error.
- Target: `>= 99.5%` per rolling 7 days.
- Burn alert: `< 99.0%` over 60 minutes.

### SLO-2: End-to-End Latency (P95)

- Definition: ingress to final assistant response for non-streaming requests.
- Target: `P95 <= 6s` for Web UI in standard load profile.
- Burn alert: `P95 > 10s` over 30 minutes.

### SLO-3: Tool Reliability

- Definition: successful tool execution ratio excluding explicit policy blocks (`approval_required`, `execution_policy_blocked`).
- Target: `>= 98.5%` per rolling 7 days.
- Burn alert: `< 97.0%` over 60 minutes.

### SLO-4: Scheduler Recoverability

- Definition: scheduled tasks resumed and executed correctly after process restart.
- Target: `100%` in restart regression suite.
- Burn alert: any failure in release-gate suite.

## Release Gates

## Gate A (PR gate)

- `cargo fmt --all --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`
- `npm --prefix web run build`
- docs drift guard: `node scripts/generate_docs_artifacts.mjs --check --no-website`

## Gate B (stability smoke)

- cross-chat permission regression suite
- sandbox runtime fallback suite
- scheduler restart/recovery suite
- web inflight/rate limit suite

## Gate C (pre-release)

- release build + startup smoke
- 24h canary (if production channel enabled)
- error budget check must be green

## Error Budget Policy

- Budget period: rolling 28 days.
- Request success SLO budget: `0.5%` failure allowance.
- If budget burn exceeds 50% before day 14:
  - freeze non-critical feature merges
  - prioritize P0 stabilization issues only
- If budget exhausted:
  - release freeze
  - rollback to last known good release if new regression confirmed

## Rollback Criteria

Trigger rollback (or immediate hotfix branch) when any is true:

- request success drops below `99.0%` for 60 minutes
- scheduler recoverability regression in production
- cross-chat auth regression (privilege escalation)
- severe data-loss/corruption bug in sessions/memory tables

## Workstreams

### W1: Observability hardening

- standardize key metrics names + labels
- dashboard: request timeline, tool failure rate, approval drop rate, fallback count
- add release baseline snapshot export

### W2: Stability test suites

- add deterministic regression suite for:
  - permissions
  - sandbox fallback and require_runtime behavior
  - scheduler restart replay
  - web concurrency/rate limits

### W3: Operability and recovery

- scheduler dead-letter queue and replay command
- failure taxonomy with user-safe and operator-diagnostic messages
- runbook updates with incident playcards

### W4: Performance and usability

- profile top latency paths in agent loop
- enforce timeout budgets and retry budgets per tool/mcp
- improve actionable error hints in UI and CLI

## Milestones

### M1 (Week 1-2)

- SLO definitions finalized and documented
- stability smoke job in CI
- issue board created with owners

### M2 (Week 3-5)

- scheduler restart suite + DLQ implementation
- fallback and policy-block metrics visible in dashboard

### M3 (Week 6-8)

- full release gates active
- first canary cycle with budget reporting

## Out of Scope (Q1)

- large new feature surfaces unrelated to reliability
- major channel expansion
- deep refactors without measurable stability benefit
