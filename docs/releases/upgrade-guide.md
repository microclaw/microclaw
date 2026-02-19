# Upgrade Guide

## Summary

This release adds:

- cookie + API key auth model with scoped permissions
- hook runtime and `microclaw hooks` CLI
- session fork metadata and APIs
- metrics APIs/history

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
