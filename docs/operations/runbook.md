# Operations Runbook

## Auth Issues

- Symptom: `401 unauthorized`
  - Check `Authorization: Bearer <api-key-or-legacy-token>` or `mc_session` cookie.
  - Verify key scopes via `GET /api/auth/api_keys`.
- Symptom: unsure whether deployment config is safe
  - Run `GET /api/config/self_check` and inspect `risk_level` + `warnings`.
  - Fix high-severity items first (`severity: high`).

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
- If OTLP is enabled, verify `channels.observability.otlp_endpoint` is reachable.
- If points are missing under burst traffic, raise `otlp_queue_capacity` and review retry settings.

If history is empty, generate traffic first and re-check.

## Stability Gate

- Run stability smoke suite locally: `scripts/ci/stability_smoke.sh`
- CI gate: `Stability Smoke` job in `.github/workflows/ci.yml`
- Scope:
  - cross-chat permissions
  - scheduler restart persistence
  - sandbox fallback and require-runtime fail-closed behavior
  - web inflight and rate-limit regression

## SLO Alerts

- Query SLO summary: `GET /api/metrics/summary`
- Request success burn alert: `slo.request_success_rate.value < 0.99`
- Latency burn alert: `slo.e2e_latency_p95_ms.value > 10000`
- Tool reliability burn alert: `slo.tool_reliability.value < 0.97`
- Scheduler recoverability alert: `slo.scheduler_recoverability_7d.value < 0.999`

When any burn alert is active:
- freeze non-critical feature merges
- triage and assign incident owner
- if user-facing impact continues, prepare rollback/hotfix path per stability plan

## Scheduler DLQ Replay

- Inspect failed scheduler runs: use tool `list_scheduled_task_dlq` with `chat_id`
- Replay pending failures: use tool `replay_scheduled_task_dlq` with `chat_id`
- Optional filters:
  - `task_id` to target one task
  - `limit` to bound replay batch size
- Replay behavior:
  - re-queues task with immediate `next_run`
  - marks DLQ entry as replayed with a replay note (`queued` or `skipped` reason)
