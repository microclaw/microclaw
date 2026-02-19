# Operations Runbook

## Auth Issues

- Symptom: `401 unauthorized`
  - Check `Authorization: Bearer <api-key-or-legacy-token>` or `mc_session` cookie.
  - Verify key scopes via `GET /api/auth/api_keys`.

- Symptom: login throttled
  - Login endpoint rate-limits repeated attempts per client key.
  - Wait for cooldown window and retry.

## Hook Issues

- List hooks: `microclaw hooks list`
- Inspect hook: `microclaw hooks info <name>`
- Disable bad hook quickly: `microclaw hooks disable <name>`

If a hook times out or crashes, runtime skips the hook and continues.

## Session Fork Issues

- Inspect tree: `GET /api/sessions/tree`
- Create branch: `POST /api/sessions/fork`
- Deleting parent session does not cascade to children.

## Metrics Issues

- Check snapshot: `GET /api/metrics`
- Check history: `GET /api/metrics/history?minutes=60`

If history is empty, generate traffic first and re-check.
