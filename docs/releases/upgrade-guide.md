# Upgrade Guide

## Summary

Use this guide for rolling upgrades that may include schema/auth/hooks/session/metrics changes.

### SDK and products v0.6.0

Server, Work, all shared Rust crates, and the web package metadata now use one
`0.6.0` version. SDK consumers should update `microclaw-core`,
`microclaw-engine`, and `microclaw-sdk` together. The SDK feature tiers remain
`minimal`, `standard`, and `full`; no compatibility shim is required for 0.5
Skill or delegated-task APIs.

Work hosts gain the same governed Skill lifecycle and durable Subagent
projections exposed by the SDK. Custom hosts should keep all Workspace writes
behind one authorization and mutation boundary even when delegated work runs
in parallel.

### SDK v0.5.0

The three public Rust crates move together to `0.5.0`. `microclaw-sdk` adds live
Skill lifecycle management, typed durable delegation projections, cancellation,
and configurable remote Worker reconnect policy. `DelegatedTask.status` is now
`DelegatedTaskStatus`; use `as_str()` when displaying it and retain the
`Unknown` case when matching exhaustively.

## Pre-Upgrade Checklist

1. Backup SQLite database (`microclaw.db`).
2. Record current config (`microclaw.config.yaml`).
3. Ensure shell runtime for hooks (`sh`) is available if hooks are used.
4. Record current binary/image version and commit SHA.

## Database Migration

On first start, schema migrations are applied automatically.

### v0.4.0

No schema migration beyond v0.3.x is required by v0.4.0.
Changes to be aware of when upgrading from any v0.3.x:

**New config sections (all backward-compatible):**

- `alerts` — opt-in operational webhook alerts (off by default; see
  [status-and-alerts](../operations/status-and-alerts.md)). No action needed
  unless you enable it; when enabled, `alerts.webhook_url` is validated
  against the configured-endpoint egress policy at startup.
- `clawhub_verify_on_load` — load-time integrity verification of
  ClawHub-installed skills against the lockfile tree hash. **Defaults to
  `block`**: a managed skill whose files were modified after install becomes
  unavailable until reinstalled. This is a deliberate fail-closed security
  default; set `warn` or `off` to restore the old behavior. Skills installed
  before tree hashing existed are never blocked (they warn until
  reinstalled), so a plain upgrade cannot strand an old install.

**Surface changes (additive):**

- `/status` now also reports scheduler DLQ depth, 24h contract verdicts,
  token-budget usage, provider failover/breaker health, and loop restart
  counters. `GET /api/governance` gains `contracts`, `provider_health`, and
  `alerts` sections.
- Every release now attaches `reliability-scorecard-<tag>.{json,md}` to its
  GitHub release assets.
- High-risk approval prompts are numbered option cards with an
  "always allow in this chat" option (standing grants, managed via
  `/approvals`); web clients get a structured `approval_required` stream
  event. See [secure-runtime](../security/secure-runtime.md#3b-structured-high-risk-approvals).
- New `microclaw canary <model>` probes a candidate model (responds +
  tool-calling) before you switch `model:` in config.
- MCP servers and A2A peers accept a `trust` tier
  (trusted/limited/sandboxed); omitted = `limited` = historical behavior.

**Post-upgrade validation additions:**

1. Run `microclaw skill verify` — confirm no unexpected `✗` rows before
   relying on `clawhub_verify_on_load: block`.
2. Send `/status` in a chat — confirm the new health lines render.
3. If alerts are enabled: temporarily set `interval_secs: 10`, verify the
   startup log line `alerts: loop started`, then restore your cadence.

### v0.3.4

Upgrading to v0.3.4 advances the SQLite schema to v43. The migration adds
Learning Foundry tracks, epochs, immutable skill candidates, paired candidate
evaluations, and per-scenario trial records. Existing chats, memories, skills,
and scheduler records are preserved; no configuration changes or manual SQL
steps are required. Back up `microclaw.db` before first startup because older
binaries do not reverse these forward-applied tables.

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
