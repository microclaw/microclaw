# Status & Webhook Alerts

Operating MicroClaw should not require Grafana. Two surfaces cover day-to-day health:
the consolidated `/status` view (pull) and opt-in webhook alerts (push).

## `/status` — one consolidated view

The `/status` chat command (any channel) and the web Governance tab show the same
runtime health picture:

- channel, resolved provider and model, session size;
- scheduled-task tallies and the **scheduler DLQ depth** (exact count, unreplayed);
- the active durable run (phase, iteration, resumability, progress) and outbound
  delivery health (pending / retrying / failed chunks);
- **completion-contract verdicts** over the last 24 h (verified vs failed);
- **token budget** usage for the chat against `token_budget.daily_per_chat`;
- **provider health**: fallback count since start, consecutive failures, and whether
  the circuit breaker is currently open;
- **supervised-loop restart counters** — a loop restarting repeatedly is a signal,
  not noise.

The web `GET /api/governance` snapshot carries the same data for dashboards and
automation (scope: read).

## Webhook alerts (opt-in, off by default)

```yaml
alerts:
  enabled: true
  webhook_url: "https://hooks.example.com/microclaw"
  interval_secs: 60              # poll cadence (min 10)
  cooldown_secs: 900             # min seconds between same-class alerts
  restart_storm_threshold: 5     # restarts within one poll = storm
```

A supervised loop polls health every `interval_secs` and POSTs JSON to
`webhook_url` when a condition trips:

| Class | Trips when |
|---|---|
| `dlq_growth` | The scheduler dead-letter queue gained unreplayed entries since the last poll. |
| `provider_down` | The LLM circuit breaker is open, or provider calls have failed 4+ times in a row. |
| `budget_exhaustion` | One or more turns were refused because a chat's daily token budget ran out. |
| `restart_storm` | `restart_storm_threshold`+ supervised-loop restarts within one poll interval. |

Body shape:

```json
{"source": "microclaw", "class": "dlq_growth", "message": "…", "generated_at": "…"}
```

Design properties:

- **First poll is baseline-only** — restarting MicroClaw never fires a burst of
  alerts about pre-existing state.
- **Per-class cooldown** (`cooldown_secs`) prevents webhook spam while a condition
  persists.
- **Egress-governed**: the webhook URL is validated against the configured-endpoint
  egress policy at startup like every other configured destination.
- **Audited**: every delivery attempt (sent or error) lands in the tamper-evident
  audit chain under `kind = "alert"`, so alert history is queryable even if the
  webhook receiver loses it.

Point `webhook_url` at anything that accepts a JSON POST: ntfy, a Slack/Discord
ingest proxy, or a couple of lines of serverless glue.
