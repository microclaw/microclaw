# Scheduled-Task Lifecycle: run caps, deadlines, random cadences

Status: **shipped** · Module: `src/schedule_lifecycle.rs`

Scheduled tasks are no longer just "forever-cron or once". Three orthogonal
lifecycle controls compose with each other and with completion contracts:

| Control | Field | Example | Meaning |
|---|---|---|---|
| Random cadence | `schedule_type: "random"`, `schedule_value: "2h..3d"` | "nudge me now and then" | After each run, the next firing lands uniformly at random inside the window — the bot "just thinks of it". Units `s/m/h/d/w/mo`; also accepts `30m-4h`. |
| Run cap | `max_runs: 3` | "remind me 3 times" | Task retires as `completed` after N runs (any cadence). |
| Deadline | `not_after: "2026-08-01T00:00:00Z"` | "until end of the month" | Task retires as `completed` once the next firing would pass the deadline — re-checked at claim time, so an already-queued task can't fire late. |

Examples (`schedule_task` tool):

```json
{"schedule_type": "random", "schedule_value": "1d..2w", "max_runs": 5,
 "prompt": "Surprise me with a paper recommendation"}

{"schedule_type": "cron", "schedule_value": "0 0 9 * * *",
 "not_after": "2026-08-01T00:00:00Z",
 "prompt": "Daily standup digest until the sprint ends"}
```

`list_scheduled_tasks` shows the full picture per task: cadence description,
`runs: 2/5` progress, `until:` deadline, contract presence, and a humanized
`next: … (in 3h 12m)` countdown.

## Stability rules (why the flexibility can't wobble the scheduler)

- Every lifecycle feature resolves to the scheduler's ONE existing primitive:
  either a concrete `next_run`, or a transition to `completed` with a logged
  reason. No new statuses, no extra background loops.
- All decisions are pure functions (`decide_next_run`, `deadline_passed`)
  with injected entropy — every edge is unit-tested without a DB or clock.
- Random windows are clamped to [1 minute, 366 days]: a typo can neither
  hot-loop the scheduler nor silence a task for years. Malformed specs are
  rejected at creation, and a stored schedule that stops being computable
  retires the task instead of looping.
- A lifecycle retirement is always `completed` — even when the final run
  failed — so DLQ auto-replay can never resurrect a task that finished its
  allotted runs. One-shot failure semantics are unchanged (`failed` + DLQ).
- `run_count` increments on every run (success or failure) in the same
  UPDATE that reschedules, so progress can't drift from reality.
