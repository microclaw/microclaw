# Tokens-per-Task Benchmark — Method

Status: **method published; first numbers pending a benchmark run** · Owner: docs/positioning
Companion: [`../../roadmap/v0.4.0-plan.md`](../../roadmap/v0.4.0-plan.md) (WS-A2)

MicroClaw's positioning claims low token overhead on small hardware. That claim is worth
nothing without a published, reproducible measurement — and a benchmark that hides its
harness deserves suspicion, including ours. This page defines the method; per-release
numbers are published alongside it once measured under this protocol.

## Canonical tasks

Five tasks, chosen to represent real assistant use rather than best-case demos. Each task
runs in a **fresh chat** with default config, on the same model, from the same prompts:

| # | Task | Prompt sketch | Completion criterion |
|---|---|---|---|
| T1 | Daily digest | "Summarize these 3 linked articles into a 10-bullet digest." | Digest delivered, all 3 sources reflected |
| T2 | Repo watch | "Check this repo's latest release and tell me what changed vs the version I named." | Correct delta reported |
| T3 | Research question | "Compare X and Y (bounded question) with sources." | Sourced comparison delivered |
| T4 | Scheduled report | "Every day at 9:00, do T1." (measure one firing) | One scheduled firing completes with contract verified |
| T5 | Inbox triage | "Here are 10 messages (pasted); triage into act/delegate/ignore with one-line reasons." | All 10 triaged |

## Protocol

1. **Pin everything**: MicroClaw version (tag), model ID, provider, config file — all
   recorded in the results table. Any comparison row must pin the competitor's version the
   same way.
2. **Fresh chat per task** (`/reset` or a new chat id), so session carry-over doesn't
   pollute attribution.
3. **One warm-up turn** ("hello") per fresh install is run and *excluded* — first-turn
   catalogs/config priming is measured separately as "cold overhead".
4. **Three runs per task**; report median and range, never a single run.
5. **Measure from the ledger, not the invoice**: MicroClaw records every provider call in
   `llm_usage_logs` (the same table token budgets and `insights` read). Extract with:

   ```sh
   scripts/bench/tokens_per_task.sh --db ~/.microclaw/microclaw.db \
     --since 2026-08-07T00:00:00Z
   ```

   For other runtimes, use their native usage accounting if it exists; otherwise measure
   at the provider dashboard with an isolated API key per runtime. Note which method each
   row used.
6. **Publish raw logs** (the per-chat rows, and transcripts where licensing allows) next
   to the summary table, and invite reproduction.

## What counts

- **Counted**: every LLM call MicroClaw makes to complete the task — agent loop,
  sub-agents, compaction, memory operations triggered by the turn.
- **Excluded**: the warm-up turn; background loops that did not run as part of the task
  (reflector, heartbeat) — run benchmarks with proactive loops at defaults (off).
- Cross-runtime comparisons must hold the *task outcome* constant, not the turn count: if
  a runtime needs three user nudges to finish T2, those turns count against it.

## Results

*No numbers are published yet under this protocol.* The first measured table lands here
with the v0.4.0 release; refresh per minor release thereafter. Do not cite this page as
evidence of relative cost until it carries data.

| Release | Model | T1 | T2 | T3 | T4 | T5 | Raw logs |
|---|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — | — |
