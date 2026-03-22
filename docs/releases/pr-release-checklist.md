# PR and Release Checklist

Last reviewed: 2026-03-05

## PR Readiness

- [ ] Scope is clear and limited to intended feature set.
- [ ] PR description includes motivation, behavior changes, and rollback notes.
- [ ] Linked issue/PR references are present (`Fixes #...` or related PR IDs).
- [ ] `CHANGELOG.md` updated when release-visible behavior changes.
- [ ] Migration impact reviewed (`schema_migrations`, compatibility paths).
- [ ] API contract changes documented (new/changed endpoints, request/response fields).
- [ ] Security-sensitive paths reviewed (auth scope, CSRF, audit events).
- [ ] Governance/support docs updated when policy or support expectations changed (`SECURITY.md`, `SUPPORT.md`, `docs/releases/release-policy.md`).
- [ ] Docs updated in both `docs/` and `website/docs/` when user-facing behavior changes.

## Required Validation

- [ ] `cargo fmt`
- [ ] `cargo clippy --all-targets`
- [ ] `cargo test`
- [ ] `npm --prefix web run build`
- [ ] `npm --prefix website run build`
- [ ] `node scripts/generate_docs_artifacts.mjs --check`
- [ ] `cargo audit`
- [ ] `cargo deny check advisories bans licenses`

## Release Gate

- [ ] Upgrade test from previous DB schema with real sample data.
- [ ] Auth flows verified (session login/logout, API key scopes).
- [ ] Session fork flows verified (`/api/sessions/fork`, `/api/sessions/tree`).
- [ ] Hook runtime sanity verified (`hooks list/info/enable/disable`).
- [ ] Metrics pipeline verified (`/api/metrics`, `/api/metrics/history`, OTLP export if enabled).
- [ ] Config self-check reviewed (`/api/config/self_check`) with no unaccepted `high` warnings.
- [ ] macOS, Linux, and Windows release assets are present and checksummed.
- [ ] Official container image tags are published and pull successfully (`ghcr.io/microclaw/microclaw`, Docker Hub mirror if enabled).
- [ ] `nix build .#microclaw` passes (Linux required; Darwin strongly recommended).
- [ ] Nixpkgs status reviewed/updated (`docs/releases/nixpkgs-upstream-guide.md`).

## Rollback Prep

- [ ] Snapshot/backup current SQLite DB.
- [ ] Keep previous binary/image available for rollback.
- [ ] Record release commit SHA and config diff.
