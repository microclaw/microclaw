# Upgrade Guide

## Summary

Use this guide for rolling upgrades that may include schema/auth/hooks/session/metrics changes.

## Pre-Upgrade Checklist

1. Backup SQLite database (`microclaw.db`).
2. Record current config (`microclaw.config.yaml`).
3. Ensure shell runtime for hooks (`sh`) is available if hooks are used.
4. Record current binary/image version and commit SHA.

## Database Migration

On first start, schema migrations are applied automatically.

- Review pending migration files and compatibility assumptions before rollout.
- No manual SQL steps are required in normal upgrades.
- For rollback, restore the DB backup instead of manually reversing SQL.

## Auth and API Migration

1. Verify operator login and session cookie flow.
2. Verify API key scopes for automation clients.
3. For cookie-authenticated write/admin APIs, include CSRF header:
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

## Recent PR References

As of 2026-03-05 (local `main` HEAD), recent merged PRs include:

- #195 `mcp: strip internal microclaw keys from forwarded args`
- #192 `Journald`
- #191 `add flake.nix`
- #190 `fix(mcp): fix streamable HTTP transport protocol compliance`
- #188 `add podman sandbox runtime support and runtime-aware diagnostics`

Update this list when preparing a release note.

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
