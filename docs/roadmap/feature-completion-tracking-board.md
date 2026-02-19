# Feature Completion Tracking Board

Last Updated: 2026-02-19

## Board Legend

- Status: `todo` | `in_progress` | `blocked` | `done`
- Risk: `low` | `medium` | `high`

## Phase Board

| Phase | Status | Exit Criteria | Risk |
|---|---|---|---|
| Phase 0 | done | RFCs + PR decomposition + DoD board committed | low |
| Phase 1 | done | auth/session/key/scope/rate-limit shipped | high |
| Phase 2 | done | 3 hook events + CLI + e2e shipped | high |
| Phase 3 | done | session fork migration + API + tests shipped | medium |
| Phase 4 | done | metrics APIs + history shipped | high |
| Phase 5 | in_progress | regression packs + docs + RC guide shipped | medium |

## PR Tracker

| PR | Title | Phase | Owner | Status | Depends On | DoD Check |
|---|---|---|---|---|---|---|
| PR-000 | Program Skeleton | 0 | core | done | - | yes |
| PR-001 | Implementation Decomposition | 0 | core | done | PR-000 | yes |
| PR-100 | Auth DB Migration | 1 | storage | done | PR-001 | yes |
| PR-101 | Password Login + Session Cookie | 1 | web | done | PR-100 | yes |
| PR-102 | API Keys with Scopes | 1 | web/storage | done | PR-100 | yes |
| PR-103 | Auth Middleware + Scope Map | 1 | web | done | PR-101, PR-102 | yes |
| PR-104 | Rate Limiting Baseline | 1 | web | done | PR-103 | yes |
| PR-105 | Auth Docs + Upgrade Notes | 1 | docs | done | PR-104 | yes |
| PR-200 | Hook Spec + Parser | 2 | runtime | done | PR-001 | yes |
| PR-201 | Hook Discovery + Eligibility | 2 | runtime | done | PR-200 | yes |
| PR-202 | Hook Runtime Executor | 2 | runtime | done | PR-201 | yes |
| PR-203 | Agent Event Wiring | 2 | runtime | done | PR-202 | yes |
| PR-204 | Hooks CLI | 2 | cli | done | PR-201 | yes |
| PR-205 | Sample Hooks + Docs | 2 | docs/runtime | done | PR-203, PR-204 | yes |
| PR-300 | Session Schema Migration | 3 | storage | done | PR-001 | yes |
| PR-301 | Fork Service Logic | 3 | runtime/storage | done | PR-300 | yes |
| PR-302 | sessions.fork API | 3 | web | done | PR-301, PR-103 | yes |
| PR-303 | Session Tree + Delete Rules | 3 | storage | done | PR-300 | yes |
| PR-304 | Fork Docs + Compatibility | 3 | docs | done | PR-302, PR-303 | yes |
| PR-400 | Metrics Registry Foundation | 4 | runtime | done | PR-001 | yes |
| PR-401 | Runtime Instrumentation | 4 | runtime/web | done | PR-400 | yes |
| PR-402 | Metrics History Storage | 4 | storage | done | PR-400 | yes |
| PR-403 | Metrics APIs | 4 | web | done | PR-401, PR-402 | yes |
| PR-404 | Metrics API Hardening | 4 | web | done | PR-401 | yes |
| PR-405 | Observability Docs + Grafana | 4 | docs | done | PR-403, PR-404 | yes |
| PR-500 | Security Regression Pack | 5 | qa | done | M1, M2, M3, M4 | yes |
| PR-501 | Performance Regression Pack | 5 | qa | done | M4 | yes |
| PR-502 | Migration Regression Pack | 5 | qa/storage | done | M1, M3, M4 | yes |
| PR-503 | Operational Docs Completion | 5 | docs | done | PR-500, PR-502 | yes |
| PR-504 | RC + Upgrade Guide | 5 | release | done | PR-503 | yes |

## Acceptance Suite Matrix

| Capability | Minimum Test Set |
|---|---|
| Auth scopes | unit + integration (read/write/admin/approvals) |
| Hook outcomes | unit + integration + e2e (allow/block/modify) |
| Session fork | migration + service + API integration |
| Metrics | registry + API + persistence + scrape format |
| Release hardening | security/perf/migration regression suites |

## Lint/CI Checklist (copy into each PR)

- [ ] `cargo test -q`
- [ ] `npm --prefix web run build`
- [ ] `npm --prefix website run build`
- [ ] `node scripts/generate_docs_artifacts.mjs --check`
- [ ] Docs updated for behavior/config changes
- [ ] Rollback note included
