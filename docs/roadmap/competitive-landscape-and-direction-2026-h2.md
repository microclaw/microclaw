# Competitive Landscape & Direction — 2026 H2

Status: **strategy** · Date: 2026-06-20 · Companion to
[`v0.3.0-self-improving-runtime.md`](./v0.3.0-self-improving-runtime.md) and
[`v0.3.0-completion-and-v0.4.0-kickoff.md`](./v0.3.0-completion-and-v0.4.0-kickoff.md)

A fresh (mid-2026) competitive-intelligence pass on the two reference projects, what it changes
for MicroClaw, and the resulting direction. Confidence is marked per claim: **[primary]** =
GitHub API / release pages / major press; **[secondary]** = aggregator/blog only, plausible but
unverified.

---

## 1. Reference projects — where they actually are (mid-2026)

### OpenClaw — `openclaw/openclaw`
- **Identity/scale [primary]:** TypeScript/Node local-first personal agent. ~**379.5k stars**,
  created 2025-11-24, active 2026-06. The single most-starred repo on GitHub. Creator Peter
  Steinberger joined OpenAI (~Feb 2026); project spun into an **OpenAI-sponsored independent
  open-source foundation** (TechCrunch, CNBC).
- **Recent confirmed work (2026.6.1) [primary]:** resilient recovery for interrupted tool calls
  / stale sessions / compaction handoffs / auth-profile failover; channel restart survival
  (WhatsApp/iMessage/Discord/QQ/iOS Talk); **Skill Workshop** (proposal→approval workflow);
  **Workboard** multi-agent coordination with task-backed runs + **SQLite-backed plugin state**;
  cron migrated to SQLite; plugin-boundary isolation.
- **`openclaw/proxyline` [primary]:** a standalone TS library for **process-global egress
  control** — replaces the Node http/https + fetch global dispatcher, **managed (fail-closed)**
  vs ambient modes, `explain()` with credential redaction, blocks metadata/private/loopback
  ranges. Premise: env-var proxies are best-effort and silently bypassable, so policy belongs in
  code.
- **Roadmap [secondary]:** deterministic multi-agent orchestration (contract-governed, *away*
  from chaotic "agent armies"); Plugin SDK v2 (typed contracts); ChromaDB vector memory (today a
  community skill, not core); operator web dashboard; enterprise (Teams/Salesforce/SSO-SAML/RBAC/
  audit); skill trust-scoring ("ClawForge").
- **Direction:** professionalizing on two axes at once — **security/operability** and
  **enterprise readiness** — while staying self-hostable. Likely open-core + managed-hosting.

### Hermes Agent — `NousResearch/hermes-agent`
- **Identity/scale [primary]:** Python (+TS) self-hosted, model-agnostic "agent that grows with
  you." ~**197.7k stars**, created 2025-07, active 2026-06. Rapid cadence (~weekly/biweekly).
- **Recent confirmed work [primary]:** v0.17 "Reach" (iMessage via Photon, **Raft** agent-network
  gateway, background/async subagents); v0.16 "Surface" (native desktop app + web admin
  dashboard); v0.15 "Velocity" (**core loop −76%**, session_search rebuilt ~4500× faster,
  **promptware injection defense**, secrets via Bitwarden, skill bundles).
- **The strategic core [primary]:** Hermes Agent is explicitly a **training-data + RL flywheel** —
  batch parallel **trajectory generation**, compression, **ShareGPT/Atropos export**; companion
  `hermes-agent-self-evolution` repo evolves **skills → prompts → tool code** via **DSPy + GEPA**
  (genetic-Pareto, human-in-the-loop PR-gated). Connected stack: Hermes Agent → **Atropos** (RL
  environments) → **Psyche/DisTrO** (decentralized low-bandwidth training of next Hermes models).
- **Direction:** own the full open-source loop **agent runtime → RL infra → decentralized
  training**; turn everyday agent behavior into trainable data. Consumer hook = "grows with you";
  long game = vertically integrated, crypto-adjacent counter-position to closed labs.

---

## 2. What the landscape tells us (convergent signals)

1. **Egress control is now an industry-validated pattern.** OpenClaw shipped a dedicated
   `proxyline` library for fail-closed, auditable, in-code network policy. This is *exactly*
   MicroClaw's planned v0.4.0 Track B item — **the direction is confirmed.**
2. **Multi-agent is converging on deterministic, contract-governed orchestration**, explicitly
   moving away from chaotic swarms (OpenClaw Workboard; Hermes Raft/Kanban). The value is in
   *governance*, not in spawning more agents.
3. **Resilience/recovery is now table stakes**, not a nice-to-have. OpenClaw's headline 2026.6.1
   work was interrupted-tool-call recovery and restart survival.
4. **Approval-gated, security-scanned skill creation is the consensus safe pattern** (OpenClaw
   Skill Workshop proposal→approval; Hermes PR-gated self-evolution). Validates "curator creates
   *disabled* skills."
5. **Self-improvement is the headline of the category** — but the two leaders take very different
   routes: Hermes pushes all the way to **evolving its own tool code + RL training**; OpenClaw
   keeps it to approval-gated skills.
6. **Both already moved runtime state into SQLite** — MicroClaw has been SQLite-native from day
   one. A structural head start on the very thing they retrofitted.

## 3. MicroClaw's position — unchanged thesis, sharpened

Both leaders are an order of magnitude larger in mindshare (379k / 197k stars) and are
Python/TypeScript. **MicroClaw cannot and should not compete on hype or breadth.** Its moat is
the one neither occupies:

> A single **static Rust binary** on a **$5 VPS** (1 vCPU / 1 GB) — channel-native,
> **secure-by-default**, that **gets better the longer it runs** — no Python stack, no vector DB,
> no training cluster.

The intel *reinforces* this. Where the leaders bolt on egress control as a separate library
(Proxyline) or retrofit SQLite, MicroClaw can ship the same capabilities **natively, in one
process, with a fraction of the footprint** — and that footprint *is* the product.

### Explicit non-goals (do not chase)
- **No RL/training flywheel** (Hermes/Atropos/Psyche). Keep only a cheap, deferred
  **Atropos-compatible trajectory *export schema*** as a researcher affordance — no training-side
  investment.
- **No code self-modification / GEPA-style evolution of the agent's own tool code.** It is
  antithetical to a secure-by-default pitch. Self-improvement stays scoped to **skills + memory**,
  approval-gated.
- **No enterprise-SaaS build-out** (ChromaDB core, SSO/SAML/Teams/Salesforce, operator
  dashboards as a product). Stay self-hostable; leave hosting to operators.
- **No "agent army."** Orchestration value is governance and contracts, not agent count.

---

## 4. Direction — confirmed plan + intel-driven adjustments

The existing v0.3.0→v0.4.0 plan holds. The intel produces **four adjustments**, not a rewrite:

| # | Adjustment | Driven by | Effect on plan |
|---|---|---|---|
| A | **Promote egress control to a headline v0.4.0 feature** and frame it as native/in-process/fail-closed (vs Proxyline-as-library). | OpenClaw Proxyline [primary] | Was already Track B; raise its prominence and lead with it. |
| B | **Raise Track C (resilience/recovery) priority to "table stakes."** Interrupted-tool-call recovery, resumable runs, scheduler DLQ replay move up. | OpenClaw 2026.6.1 recovery focus [primary] | Track C groundwork starts *in parallel with* v0.3.0 finish, not after. |
| C | **Formalize `subagents_orchestrate` into a contract-governed orchestration story** (a Workboard analog: declared tasks, dependencies, deterministic routing, fan-in). | OpenClaw Workboard + Hermes Raft [primary] | New v0.4.0 line item; builds on existing subagents. |
| D | **Keep the skill curator deterministic and skills-only**; explicitly *reject* code/prompt self-evolution. Add the trajectory-export schema as a deferred researcher affordance. | Hermes self-evolution as cautionary contrast [primary] | Tightens P2 scope; no new heavy work. |

### Resulting sequence

**v0.3.0 finish (unchanged order, from the completion doc):**
1. Skill curator (P2) — deterministic, skills-only, creates *disabled* + security-scanned skills.
2. Finish guardrails (P5b) — warn→block policy + post-output secret/PII scan.
3. Sandbox credential hygiene (P4c), then gVisor/SSH backends.

**v0.4.0 — "Secure-by-default, durable, governed" (intel-adjusted):**
4. **Native network egress control** (Track B headline; fail-closed, auditable, in-process).
5. **Per-chat / per-agent least-privilege tool authorization** (OWASP Agentic Top 10).
6. **Resilience/recovery** (Track C, now table stakes): interrupted-tool-call recovery, resumable
   long runs, scheduler **DLQ + replay**, non-web progress heartbeat.
7. **Contract-governed orchestration** (formalize `subagents_orchestrate`: declared tasks,
   dependencies, deterministic fan-in).

**Deferred (researcher/long-horizon):** Atropos-compatible trajectory *export schema* only;
Live Canvas / A2UI, mobile nodes, serverless hibernate (per #378 Q4/2027).

### Guarantees (unchanged)
No default behavior change; every new autonomous or isolation-changing feature off by default;
aux-model slots fall back to main. Per-PR checklist from `feature-completion-tracking-board.md`
applies.

---

## 5. Sources

**OpenClaw [primary]:** github.com/openclaw/openclaw · github.com/openclaw/openclaw/releases/tag/v2026.6.1
· github.com/openclaw/proxyline · techcrunch.com/2026/02/15/openclaw-creator-peter-steinberger-joins-openai
· cnbc.com (2026-02-15). **[secondary roadmap]:** tencentcloud techpedia 141252; blink.new; skywork.ai.

**Hermes Agent [primary]:** github.com/NousResearch/hermes-agent · hermes-agent.nousresearch.com/docs
· github.com/NousResearch/hermes-agent-self-evolution · github.com/NousResearch/atropos ·
nousresearch.com/nous-psyche. **[secondary]:** marktechpost (2026-06-03 Hermes Desktop); petronellatech tracker.

*Caveat:* both projects' roadmap specifics rest on secondary sources (official docs/blogs blocked
automated fetching); confirmed release content and repo metadata are primary. Re-verify before
treating any [secondary] item as load-bearing.
