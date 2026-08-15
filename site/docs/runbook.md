---
id: runbook
title: Operations Runbook
sidebar_position: 23
---

Use this page for quick operator triage. The full repository reference lives in [`docs/operations/runbook.md`](https://github.com/microclaw/microclaw/blob/main/docs/operations/runbook.md).

## Auth checks

- `401 unauthorized`:
  - verify `Authorization: Bearer <api-key>` or the `mc_session` cookie
  - inspect scopes with `GET /api/auth/api_keys`
- Safety review:
  - run `GET /api/config/self_check`
  - fix `severity: high` warnings first
- Login throttling:
  - wait for the cooldown window and retry

## Gateway bridge checks

- The Mission Control-compatible WebSocket bridge is served from `GET /` with WebSocket upgrade.
- Quick smoke:

```sh
MICROCLAW_GATEWAY_TOKEN=... microclaw gateway call health
MICROCLAW_GATEWAY_TOKEN=... microclaw gateway call status
MICROCLAW_GATEWAY_TOKEN=... microclaw gateway call sessions_send \
  --params '{"sessionKey":"main","message":"status summary"}'
```

- Supported operator methods:
  - `health`, `status`, `chat.send`, `chat.history`
  - `session_delete`, `sessions_send`, `sessions_kill`, `sessions_spawn`
  - `session_setThinking`, `session_setVerbose`, `session_setReasoning`, `session_setLabel`
- Expected live events:
  - `connect.challenge`
  - `chat`
  - `tick`

## Session controls

- Session tree: `GET /api/sessions/tree`
- Fork session: `POST /api/sessions/fork`
- Delete session: Web API `POST /api/delete_session` or bridge `session_delete`
- Kill active run: bridge `sessions_kill`
- Persist per-session label/settings:
  - `session_setLabel`
  - `session_setThinking`
  - `session_setVerbose`
  - `session_setReasoning`

## Metrics and SLOs

- Snapshot: `GET /api/metrics`
- History: `GET /api/metrics/history?minutes=60`
- Summary/SLOs: `GET /api/metrics/summary`
- OTLP gaps under burst traffic:
  - raise `otlp_queue_capacity`
  - review retry settings and endpoint reachability

## Stability checks

- Local smoke: `scripts/ci/stability_smoke.sh`
- CI job: `Stability Smoke`
- When SLO burn alerts fire:
  - freeze non-critical feature merges
  - assign an incident owner
  - prepare rollback or hotfix if user impact continues
