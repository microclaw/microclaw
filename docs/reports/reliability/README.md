# Reliability Scorecard

Every MicroClaw release ships with a reproducible reliability scorecard: a fixed set of
failure-injection scenarios executed against the release source, with a machine-readable
verdict per scenario. Competitors *claim* durability; this page documents how MicroClaw
*shows* it.

## Where to find it

- **Per release**: `reliability-scorecard-<tag>.json` and `reliability-scorecard-<tag>.md`
  are attached to every [GitHub release](https://github.com/microclaw/microclaw/releases)
  alongside the binaries, generated from the exact tagged source by the release pipeline.
- **Per CI run**: the `Stability Smoke` job in CI uploads a `reliability-scorecard`
  artifact (JSON + Markdown + per-scenario logs) for every push to `main`.
- **Locally**: reproduce the whole pack with one script from a source checkout:

  ```sh
  scripts/ci/reliability_scorecard.sh --output-dir /tmp/scorecard
  ```

  The script exits non-zero if any scenario fails; results land in
  `scorecard.json`, `scorecard.md`, and `logs/` under the output directory.

## What it proves

The pack currently exercises six categories (see
[`scripts/ci/reliability_scorecard.sh`](../../../scripts/ci/reliability_scorecard.sh) for
the authoritative list — the script is the source of truth, this table is a guide):

| Category | Scenarios |
|---|---|
| `recovery` | A safe active-turn checkpoint survives a second recovery restart; scheduled work survives a database reopen; a failed scheduled run replays from the durable dead-letter queue. |
| `delivery` | Interrupted chunk delivery resumes without duplicating the logical message; long messages preserve every byte across chunk boundaries; splitting never cuts a UTF-8 code point. |
| `rate_limit` | The request rate-limit window recovers after backoff; common delivery rate-limit failures are classified retryable. |
| `timeout` | A timed-out command is terminated and reported as a timeout. |
| `provider_boundary` | Malformed provider wrappers are normalized without poisoning stored history; private reasoning and fake tool traces are stripped before delivery. |
| `security` | Cross-chat tool permissions remain fail-closed; a required sandbox fails closed when its runtime is unavailable. |

Each scenario is an ordinary test in the repository, so a failed scenario points at a real
regression with a log, not a marketing table.

## Schema

`scorecard.json` (`schema_version: 1`):

```json
{
  "schema_version": 1,
  "generated_at": "<UTC timestamp>",
  "release": "<Cargo package version>",
  "summary": {"total": 13, "passed": 13, "failed": 0},
  "cases": [
    {"id": "process-restart", "category": "recovery", "status": "pass",
     "duration_ms": 0, "description": "…", "evidence": "logs/process-restart.log"}
  ]
}
```

`evidence` paths refer to the per-scenario logs, which are included in the CI artifact
(release assets carry the JSON and Markdown summaries; logs stay in the CI artifact for
size reasons).

## Comparison caveats

The scorecard proves the in-repository MicroClaw baseline. It does not claim cross-project
superiority: comparing against another runtime requires running the *same* scenarios,
payloads, retry windows, and pinned versions on that runtime. Treat any cross-project
number that does not publish its harness with suspicion — including ours.
