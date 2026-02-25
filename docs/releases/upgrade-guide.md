# Upgrade Guide

## Summary

This release adds:

- cookie + API key auth model with scoped permissions
- hook runtime and `microclaw hooks` CLI
- session fork metadata and APIs
- metrics APIs/history
- slash-command behavior change: `/stop` now aborts the active run for the current chat (it no longer clears chat history/session data)

## Pre-Upgrade Checklist

1. Backup SQLite database (`microclaw.db`).
2. Record current config (`microclaw.config.yaml`).
3. Ensure shell runtime for hooks (`sh`) is available if hooks are used.

## Database Migration

On first start, schema migrates to include:

- auth tables (`auth_passwords`, `auth_sessions`, `api_keys`, `api_key_scopes`)
- session fork columns (`sessions.parent_session_key`, `sessions.fork_point`)
- metrics history table (`metrics_history`)

No manual SQL steps are required.

## Auth Migration

1. Keep existing web auth token for transition.
2. Set operator password through `POST /api/auth/password`.
3. Create scoped API keys as needed.
4. Roll client automation from legacy token to API keys.

For cookie-authenticated write/admin APIs, include CSRF header:

- Header: `x-csrf-token: <token>`
- Token is returned by `POST /api/auth/login` and mirrored in `mc_csrf` cookie.

## Hooks Rollout

1. Add hooks under `hooks/<name>/HOOK.md`.
2. Verify discovery with `microclaw hooks list`.
3. Enable one-by-one with `microclaw hooks enable <name>`.

## Post-Upgrade Validation

1. `GET /api/health`
2. `GET /api/auth/status`
3. `GET /api/sessions/tree`
4. `GET /api/metrics`
5. `GET /api/config/self_check` (no unaccepted `high` warnings)
6. In any chat, start a long-running request and send `/stop`; verify the in-flight run is aborted.
7. Verify `/reset` still clears chat context (session + chat history) as before.

## Merge Notes (PR #40)

Scope in this release:

- web runtime modularization (`web/auth.rs`, `web/sessions.rs`, `web/metrics.rs`, `web/config.rs`, `web/stream.rs`)
- config self-check API + Web UI warning surfacing
- OTLP exporter queue/bounded retry behavior hardening
- release/process docs updates

Operational risk notes:

- startup self-check warnings should be reviewed before production rollout
- cookie-authenticated write/admin calls require CSRF token header
- OTLP is optional; when enabled, validate endpoint reachability and retry settings

## Rollback Procedure

If release validation fails after deploy:

1. Stop the new process.
2. Restore previous binary/image version.
3. Restore pre-upgrade `microclaw.db` backup.
4. Restore previous `microclaw.config.yaml`.
5. Start old version and run:
   - `GET /api/health`
   - `GET /api/auth/status`
   - `GET /api/sessions`
6. Record incident notes, failure symptom, and migration/schema version.

Notes:

- migrations are forward-applied on startup; DB restore is the safe rollback path
- do not partially replay migration SQL by hand during incident rollback
