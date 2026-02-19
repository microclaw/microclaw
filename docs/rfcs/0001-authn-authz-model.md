# RFC 0001: Web Authentication and Authorization Model

- Status: Draft
- Owner: runtime/web
- Target Phase: Phase 1
- Last Updated: 2026-02-19

## Context

MicroClaw web APIs currently rely on a single bearer token gate for most routes.
This is insufficient for role separation, key rotation, and operator workflows.

## Goals

- Replace single-token-only model with session-cookie + API key auth.
- Introduce scoped authorization: `operator.read`, `operator.write`, `operator.admin`, `operator.approvals`.
- Add baseline request throttling for login and sensitive endpoints.
- Keep backwards compatibility path during rollout.

## Non-Goals

- WebAuthn/passkey in this phase.
- Full multi-tenant RBAC.

## Proposed Design

### Identity Types

- Session identity (browser login)
- API key identity (automation/client)

### Scope Semantics

- `operator.read`: read-only status/history/config read
- `operator.write`: send messages, mutate settings/tasks/sessions
- `operator.admin`: superset of all scopes
- `operator.approvals`: resolve high-risk tool approvals

Scope evaluation rule:

1. `operator.admin` always passes
2. Otherwise endpoint-required scopes must all be satisfied

### Data Model

Add tables (SQLite):

- `auth_passwords`
- `auth_sessions`
- `api_keys`
- `api_key_scopes`

Fields to include:

- password hash + created_at/updated_at
- session id, user label, expiry, last_seen, revoked_at
- api key hash, label, created_at, revoked_at
- one-to-many key->scope rows

### Middleware

- `auth_gate`: route-level auth+scope gate
- `throttle_gate`: per-ip bucket limits for:
  - login endpoints
  - auth endpoints
  - mutation-heavy endpoints

### API Surface

- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/status`
- `POST /api/auth/api_keys`
- `GET /api/auth/api_keys`
- `DELETE /api/auth/api_keys/{id}`

## Backward Compatibility

- Keep `web_auth_token` as temporary fallback behind config switch:
  - `auth_legacy_token_fallback = true` (default true in first release)
- Emit startup warning when fallback path is used.

## Security Considerations

- Store only hashed API keys.
- HTTP-only session cookie, SameSite=Strict, secure when TLS enabled.
- Explicit key revocation and expiry checks.

## Migration Plan

1. Create tables and indexes with idempotent migration.
2. Deploy middleware with fallback enabled.
3. Expose API key/session APIs.
4. Disable fallback in a later minor release.

## Testing Plan

- Unit tests: scope evaluator, cookie parser, key hash/verify.
- Integration tests: protected route matrix by scope.
- Regression tests: legacy token fallback behavior.

## Rollback Plan

- Keep old token check path toggled by config.
- DB additive migration; safe to keep tables unused.
