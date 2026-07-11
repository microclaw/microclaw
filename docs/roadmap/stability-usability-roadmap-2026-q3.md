# Stability & Usability Roadmap — 2026 Q3

Status: **strategy** · Date: 2026-07-11 · Horizons: 2 weeks / 1 month / 3 months
Companions: [`competitive-intel-update-2026-07.md`](./competitive-intel-update-2026-07.md) ·
[`v0.3.0-completion-and-v0.4.0-kickoff.md`](./v0.3.0-completion-and-v0.4.0-kickoff.md) ·
[`../completion-contracts.md`](../completion-contracts.md)

## 0. Thesis for this quarter

The June–July capability sprint landed the differentiators (tool policy, token
budget, heartbeat, /learn, ClawHub hardening, the full completion-contract
engine). The category's center of gravity — visible in OpenClaw's
reliability-only June release and LTS talk, and Hermes zeroing ~700 P0/P1s in
v0.18 — has moved from *what an agent can do* to *whether you can depend on
it*. MicroClaw's pitch ("a $5-VPS binary that gets better the longer it runs")
is only true if it also **runs long**: this quarter pivots from capability to
**dependability** — stability you can measure, usability you can feel in the
first five minutes.

> Build nothing new that isn't in service of: a user survives their first 10
> minutes without reading source, and a bot survives 30 days unattended.

## 1. Where the project actually stands (July 2026 review)

**Strengths (keep compounding):**
- Security/governance stack is ahead of both reference projects for its size:
  tool_policy at the registry choke point, tamper-evident audit chain, output
  guardrail, per-chat token budget, sandboxed + policy-gated command
  execution, ClawHub bounded-extraction + local injection scan.
- Trust surface nobody else ships complete: completion contracts across
  sub-agents, orchestration fan-in, scheduled tasks, and ACP.
- Reliability groundwork: scheduler DLQ + auto-replay, provider fallback,
  structured sub-agent output, eval gate in CI.

**Gaps found in this review (ordered by risk):**

| # | Gap | Evidence | Risk |
|---|---|---|---|
| 1 | **`stable` branch is stale at v0.2.3 (Jun 11), 20 commits behind main** — while README now sends stability-seeking users there. It lacks every security feature shipped since (output guardrail, tool_policy, ClawHub hardening, dependency CVE bumps). | `git log 3ff2899..main` | README actively directs users to a *less safe* build. Most urgent item in this plan. |
| 2 | No release/promotion process: no cadence, no soak criteria, no upgrade guide per release, CHANGELOG drifts. | releases/ docs are policy fragments | "Stable" is a label, not a process. |
| 3 | Interrupted-turn recovery missing: a crash/restart mid-agent-turn loses the in-flight run silently (scheduled runs recover via DLQ; interactive turns don't). | agent_engine has no resume path | OpenClaw made this their 2026.6.1 headline — table stakes. |
| 4 | Two env-dependent hook tests fail in exec-restricted containers — dev/CI parity noise that trains people to ignore red. | hooks::tests, agent_engine::tests | Broken-windows effect on test discipline. |
| 5 | New governance knobs (tool_policy, token_budget, heartbeat, contracts) are config-file/tool-call only — invisible in the web settings panel; config errors surface late. | web/config.rs coverage | The differentiators exist but aren't *operable* by non-experts. |
| 6 | Long-task feedback on non-web channels still Phase-3-pending (typing indicator only); budget refusals/contract failures read like system logs. | non-web-channel-progress-events-plan.md | Usability of the flagship "8-hour coworker" story. |
| 7 | No leak/soak evidence: Stability Smoke is minutes-long; no RSS-over-24h data, no crash-free-days metric. | CI workflow | "Runs for a month on 1GB RAM" is asserted, not measured. |

## 2. Horizon 1 — next 2 weeks (7/11 → 7/25): "Stable is a process, not a label"

**Theme: release engineering + reliability baseline. No new features.**

1. **Rescue the stable branch (day 1–2).** Promote current main (post-#457) to
   `stable` after a 48h soak; tag `v0.3.0` (the self-improving-runtime release
   is, in substance, done). Write `docs/releases/stable-promotion-policy.md`:
   main soaks N days → cherry-pick-only stabilization → tag → `stable`
   fast-forward; security fixes always backported. README notice then becomes
   true instead of aspirational.
2. **Release cadence + SemVer discipline.** Minor every ~4 weeks from a soaked
   main; patch releases on demand for security. CHANGELOG generated per tag
   (the PR titles this month are already changelog-quality).
3. **Fix the two env-dependent hook tests** — detect exec-restricted
   environments and `skip` with a reason instead of failing; CI keeps running
   them for real. Zero tolerated-red anywhere.
4. **24h soak job (nightly, not per-PR).** Extend Stability Smoke into a
   scheduled workflow: run the bot against a mock provider with scripted
   traffic for 24h; track RSS, open FDs, SQLite size, scheduler drift; fail on
   regression thresholds. Publish the graph in the repo (the "$5 VPS" pitch
   becomes a measured artifact).
5. **Crash-visibility pass.** Every `tokio::spawn` loop already goes through
   `spawn_guarded`; add restart counters to `insights`/`doctor` so silent
   panic-restart loops become visible ("scheduler restarted 14× today" is a
   page, not a mystery).

*Exit criteria:* stable == v0.3.0 tag; promotion policy doc merged; CI has
zero known-red tests; first 24h soak graph committed; `doctor` shows restart
counters.

## 3. Horizon 2 — weeks 3–6 (7/25 → 8/22): "The first ten minutes"

**Theme: usability. A newcomer goes zero → talking bot with guardrails in 10
minutes, without reading source.**

1. **Onboarding path hardening.** `setup` wizard already validates channels
   and credentials; add an end-of-wizard "first conversation" self-test (send
   a message through the configured channel via the bot itself) so success is
   demonstrated, not assumed. Measure and publish "time-to-first-reply".
2. **Config diagnostics.** `microclaw config check`: schema-validated, line-
   precise errors, "did you mean" for misspelled keys (the tool_policy enum
   work set the pattern — typos fail at load, everywhere). Every failure
   message names the file, the key, and the fix.
3. **Web settings parity for the new governance surface.** tool_policy, token
   budget, heartbeat, contracts visibility (recent verdicts), skill curator
   status — visible and editable in the web panel. The differentiators must
   be operable by someone who never opens YAML.
   *First slice shipped 2026-07:* read-only governance snapshot
   (`/api/governance` + Governance tab: tool policy, token budget, heartbeat,
   progress heartbeats, loop restarts, task health) and a full scheduled-task
   management tab (`/api/tasks` list/pause/resume/cancel + run history).
   Editing still happens in config.yaml.
4. **Long-task feedback, non-web channels** (Phase 3 of the progress-events
   plan): periodic one-line progress edits on Telegram/Discord/Slack for runs
   >30s, wired to the existing `report_progress` events. Budget refusals and
   contract failures get human phrasing (bilingual zh/en message catalog —
   the user base warrants it; Hermes shipped full zh in v0.16).
   *Progress edits shipped 2026-07* on Telegram/Discord/Slack (opt-in
   `channels.<name>.progress_updates`); message catalog still open.
5. **Task-oriented cookbook.** Five recipes end-to-end, each with a completion
   contract: daily digest, repo watcher, backup-with-verification, weekly
   report PDF, inbox triage. Usability of docs *is* usability of product.
6. **`microclaw upgrade` dry-run.** Show config keys added/deprecated between
   the running version and the target before touching anything.

*Exit criteria:* new-user path timed <10 min on a clean VPS; config errors
always actionable; governance panel shipped; progress edits live on ≥2
channels; cookbook merged.

## 4. Horizon 3 — month 2–3 (8/22 → 10/10): "v0.4.0: dependable by default + first LTS"

**Theme: finish the security pillar, make operations self-explaining, cut LTS-1.**

1. **Native egress control** (Track B headline, unchanged from the kickoff
   doc): process-level outbound policy — private/metadata ranges blocked by
   default, allow-list opt-in, `explain`-style audit of denials. Warn-only
   first release, block the next.
2. **Per-chat least-privilege tool authorization**: scope tools to chats/roles
   on top of tool_policy (the OWASP agentic top-10 root cause is
   over-permissioning). Web panel edits it; audit chain records grants.
3. **Sandbox credential hygiene (P4c) + gVisor backend**: sandboxed processes
   never see raw API keys; secrets injected only at the egress boundary.
4. **Durable interactive runs (Track C)**: persist agent-loop checkpoints so a
   restart mid-turn resumes or cleanly reports "I was interrupted, here's
   where I got to" — never silence. Channel delivery outbox with retry, so a
   flaky Telegram outage can't drop a finished answer.
   *"Never silence" half shipped 2026-07* (`src/turn_recovery.rs`): interactive
   turns are tracked in `active_turns`, restart notifies the affected chats,
   and orphaned sub-agent runs retire as `interrupted`. Checkpoint/resume and
   the delivery outbox remain.
5. **Operability surface**: one `/status` web page + bot command showing runs,
   DLQ depth, contract verdict rates, token spend vs budget, provider
   failovers, restart counters; optional webhook alerts (DLQ growth, provider
   down, budget exhaustion). Self-hosting must not require Grafana.
6. **LTS-1 (v0.4.0-lts, early October)**: 3-month support window,
   security-backports-only; migration tool from any v0.3.x config/DB. This is
   the answer to OpenClaw's LTS talk, sized for self-hosters.

*Exit criteria:* OWASP agentic top-10 self-assessment published; kill -9
during an interactive turn produces a resumed-or-explained outcome, never
silence; LTS-1 tagged with upgrade guide; status page ships.

## 5. Foresight bets (small now, compounding later)

Deliberately small investments where the category is likely heading:

- **Weekly "trust report"** (opt-in digest): what the agent did, what was
  contract-VERIFIED, tokens/cost, guardrail interventions. Trust is becoming
  the category's product surface; nobody renders it for end users yet. Cheap:
  insights + contracts + audit chain already hold all the data.
- **Model-swap canary**: before switching `model:` in config, run the existing
  eval gate against the new model and show the diff ("swap models without
  faceplants" — recurring pain as providers churn models monthly).
- **Skill lockfile pinning**: extend the ClawHub lockfile's content hashes to
  verify at *load* time, not just install time — closes the
  post-install-mutation window; ready for registry signatures when ClawHub
  ships them.
- **Tokens-per-task benchmark, published**: Hermes' loudest criticism is cost
  drift; MicroClaw's counter-position should be a number, refreshed per
  release, not a vibe.
- **A2A/MCP trust tiers**: per-server trust level (trusted/limited/sandboxed)
  mapping onto tool_policy risk — MCP marketplace incidents are the next
  ClawHavoc; the primitive exists, name the policy now.

## 6. Non-goals (re-affirmed)

No enterprise SaaS build-out, no RL/training flywheel, no desktop-app race,
no agent armies, no vector-DB core dependency. Every horizon above serves the
same defensible position: **the dependable, secure-by-default, single-binary
agent runtime for people who own their infrastructure.**

## 7. Risks

- *Stable-branch promotion churn*: promoting main monthly means regressions
  reach stable within weeks — mitigated by the 48h soak + cherry-pick-only
  window + the 24h nightly soak catching leaks before promotion.
- *Usability work is unbounded*: timebox to the enumerated items; the
  10-minute metric is the scope fence.
- *Egress control breaks setups*: ship warn-only first (same playbook as
  tool_policy/output guardrail — observe, then enforce).
- *Solo-maintainer bus factor*: the promotion policy and release checklists
  must be executable by "anyone + CI", not tribal knowledge.
