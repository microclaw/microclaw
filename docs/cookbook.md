# MicroClaw Cookbook — five real tasks, end to end

Five copy-paste recipes that exercise the parts of MicroClaw that make it a
dependable coworker rather than a chat toy: **scheduled tasks** (cron / once /
random cadences, run caps, deadlines) and **completion contracts** (the run
only counts as done when verifiable exit criteria pass).

Every recipe is something you say to the bot in chat — MicroClaw's tools are
driven by conversation, so "installation" is one message. The JSON shown is
what the agent sends to the `schedule_task` tool; you can paste the natural-
language request instead and let the agent fill it in. Where a recipe writes
files, paths are relative to the bot's working directory for your chat.

Contract crash course (full reference: `docs/completion-contracts.md`):

| Criterion | Meaning |
|---|---|
| `{"type": "file_exists", "path": "report.md"}` | File must exist after the run |
| `{"type": "file_contains", "path": "report.md", "needle": "## Summary"}` | File must contain the string |
| `{"type": "file_min_bytes", "path": "out.pdf", "min_bytes": 10240}` | File must be at least N bytes |
| `{"type": "result_contains", "needle": "done"}` | Agent's final reply must contain the string |
| `{"type": "command", "run": "cargo test -q", "expect_contains": "ok"}` | Shell command must exit 0 (and optionally print the string) |

A run whose contract fails is reported as FAILED with the failing criterion —
it can't quietly pretend success.

---

## 1. Daily digest (cron + result contract)

> "Every workday at 9am, give me a digest: top HN stories about Rust and AI
> agents, plus anything new in my watched repos. End with the word DIGEST-OK."

```json
{
  "schedule_type": "cron",
  "schedule_value": "0 0 9 * * 1-5",
  "prompt": "Compile my morning digest: search the web for the top new Hacker News stories about Rust and AI agents (last 24h), summarize the 5 most interesting with links, then check https://github.com/microclaw/microclaw/releases for anything new. Keep it under 30 lines. End with DIGEST-OK.",
  "exit_criteria": [
    {"type": "result_contains", "needle": "DIGEST-OK"}
  ]
}
```

Why the marker? A model that hits an error midway tends to apologize and stop
— the apology won't contain `DIGEST-OK`, so the run is recorded as failed and
you can see it in `list_scheduled_tasks` / the web panel instead of silently
getting a half-digest.

## 2. Repo watcher (cron + file contract)

> "Every 2 hours, check microclaw/microclaw for new issues and PRs. Keep a
> running log file; ping me only when something new appeared."

```json
{
  "schedule_type": "cron",
  "schedule_value": "0 0 */2 * * *",
  "prompt": "Check https://github.com/microclaw/microclaw for issues or PRs opened since the last entry in repo-watch.log (create the file if missing). Append one line per new item: ISO timestamp, number, title, URL. If there were new items, message me a one-line summary; otherwise stay silent.",
  "exit_criteria": [
    {"type": "file_exists", "path": "repo-watch.log"}
  ]
}
```

The log file doubles as the watcher's memory: each run reads its own previous
output, so "new since last time" needs no extra state.

## 3. Backup with verification (cron + command contract)

> "Nightly at 3am, back up my notes directory and *prove* the archive is
> restorable."

```json
{
  "schedule_type": "cron",
  "schedule_value": "0 0 3 * * *",
  "prompt": "Create backups/notes-$(date +%F).tar.gz from the notes/ directory, then verify it: list the archive and check it contains at least as many files as notes/ currently has. Delete backups older than 14 days. Reply with the archive name, file count, and size.",
  "exit_criteria": [
    {"type": "command", "run": "sh -c 'tar -tzf backups/notes-$(date +%F).tar.gz > /dev/null'"},
    {"type": "command", "run": "sh -c 'find backups -name \"notes-*.tar.gz\" -mtime -1 | grep .'"}
  ]
}
```

This is the recipe where contracts earn their keep: `tar -tzf` actually reads
the archive, so a truncated or corrupt backup fails the run loudly — the exact
failure mode that silent backup cron jobs are notorious for.

## 4. Weekly report (cron + deadline + min-size contract)

> "Every Friday at 4pm until the end of the quarter, write my weekly status
> report as a file I can attach."

```json
{
  "schedule_type": "cron",
  "schedule_value": "0 0 16 * * 5",
  "not_after": "2026-10-01T00:00:00Z",
  "prompt": "Write my weekly status report to reports/week-$(date +%G-W%V).md: pull this week's completed scheduled-task runs and chat highlights, structure it as ## Done / ## In progress / ## Next week, then send me the file.",
  "exit_criteria": [
    {"type": "command", "run": "sh -c 'f=reports/week-$(date +%G-W%V).md; test -s \"$f\" && grep -q \"## Done\" \"$f\"'"},
    {"type": "result_contains", "needle": "week-"}
  ]
}
```

`not_after` retires the task by itself when the quarter ends — no cleanup
reminder needed. Run progress shows as `runs: N` with `until: 2026-10-01` in
`list_scheduled_tasks` and the web panel's Tasks tab.

## 5. Inbox triage nudge (random cadence + run cap)

> "A few times over the next two weeks, at unpredictable moments, remind me to
> clear my inbox — 5 times total, then stop."

```json
{
  "schedule_type": "random",
  "schedule_value": "8h..2d",
  "max_runs": 5,
  "prompt": "Nudge me to spend 15 minutes clearing my inbox. Vary the phrasing; include one concrete tip for faster triage.",
  "exit_criteria": [
    {"type": "result_contains", "needle": "inbox"}
  ]
}
```

The random window (`8h..2d`, units `s/m/h/d/w/mo`) makes each next firing land
uniformly at random inside the window — the bot "just thinks of it", which
beats a fixed-time reminder you learn to ignore. `max_runs: 5` retires the
task as completed after the fifth nudge, even if some runs failed.

---

## Operating the results

- **In chat**: `list_scheduled_tasks` shows cadence, `runs: 2/5`, deadline,
  contract presence, and a humanized `next: … (in 3h 12m)`.
- **Web panel** → *Tasks* tab: the same picture across all chats, plus
  pause / resume / cancel and per-task run history with verdicts.
- **Web panel** → *Governance* tab: 24h run/success counts, contract
  coverage, dead-letter queue depth, and the reply-delivery outbox.
- Failed runs land in the DLQ and are auto-replayed with backoff; lifecycle
  retirements (`max_runs`, `not_after`) are final and never resurrected.
