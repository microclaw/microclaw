# Capability Deepening — 2026 H2

Status: **strategy** · Date: 2026-06-20 · Companion to
[`competitive-landscape-and-direction-2026-h2.md`](./competitive-landscape-and-direction-2026-h2.md)

Five capability axes we want to deepen — **smarter · more human · better at research · more
stable · security** — each grounded in what already exists, the gap, and the concrete, in-idiom
way to close it. The throughline is **measurement**: every axis extends the `microclaw eval`
trajectory harness first, so "better" is provable and regressions are caught, not vibes.

> The guiding constraint is unchanged: single static Rust binary on a $5 VPS, secure-by-default,
> deterministic where possible. Self-improvement stays scoped to **skills + memory** (never
> self-modifying tool code), and human-likeness stays **heuristic + auditable** (never LLM
> improvisation of personality).

---

## 0. The throughline — eval first

`src/eval.rs` already gates trajectories in CI (tool choice, argument validity, termination,
loop/error detection). **Rule: each axis below adds its own eval dimension before shipping the
feature.** Examples: research → citation coverage + source independence on a fixture question;
stability → resume-after-crash fixture; guardrails → a blocked-tool fixture. Without the brake,
autonomous/"smarter" features drift.

## 1. Smarter — close the self-improvement loop

- **Have:** aux models (shipped), graph-augmented memory, 42 skills, sub-agents, MCP.
- **Gap:** the agent *uses* skills but cannot *create* them from experience (no `skill_curator.rs`).
- **Do:** background **Skill Curator** (P2 from the v0.3.0 plan) — scan recurring ≥5-step
  trajectories, a cheap aux-model call decides if a reusable skill is warranted, generate a
  **disabled, security-scanned** skill via the ClawHub `gate.rs` path; restricted to control
  chats; auto-archive never-activated skills. Add post-task self-reflection that writes lessons
  to memory.
- **Non-goal:** Hermes-style DSPy/GEPA evolution of prompts/**tool code** — antithetical to
  secure-by-default. Skills + memory only, deterministic and auditable.
- **Eval:** on seeded repetitive sessions, curator proposes ≥1 correct disabled skill; no curated
  output runs without explicit activation.
- **Priority: highest** (the moat).

## 2. More human — without giving up determinism

- **Have (already deep):** `src/mood.rs` (mood heuristics), `src/relationship.rs` (familiarity),
  multi-bubble replies, idle check-in, group etiquette, `SOUL.md`.
- **Gap (open per `docs/IMPLEMENTED.md`):** inter-specialist collaboration, inner monologue,
  spontaneous humor, **personality growth**.
- **Do:** let the SOUL evolve **slowly and auditably** with relationship depth (same philosophy as
  memory decay — heuristic, logged to the audit trail, reversible), not free LLM rewriting of
  personality. Inner-monologue / proactive thoughts ride the existing idle-checkin SKIP machinery
  (only surface when high-value).
- **Constraint:** human-likeness vs secure/deterministic pulls against each other — keep all
  persona changes heuristic, conservatively triggered, and auditable.
- **Priority: later** — most exploratory; ship only once eval can detect persona regressions.

## 3. Better at research — the highest-leverage differentiator

- **Have:** `web_search`, `web_fetch` (SSRF-guarded), `browser`, `researcher` specialist persona,
  `research` skill, sub-agents. **(Foundation shipped — see below.)**
- **Shipped (this cycle):** pluggable search backends (DuckDuckGo / SearXNG / Brave / Tavily) and
  a deterministic **`deep_research`** tool — fan-out sub-queries → dedup → SSRF-guarded concurrent
  fetch → citation-numbered digest with source-agreement signals. Tool does the mechanical gather;
  the agent does semantic cross-verification + synthesis with citations.
- **Next:** promote `researcher` into a true deep-research **workflow** (this is the best first use
  case for v0.4.0 contract-governed orchestration: planner splits sub-questions → research
  sub-agents fan out → adversarial verifier flags conflicts → cited synthesis); structured
  source/citation store; optional SearXNG bundled in the setup wizard (no key, $5-VPS-friendly).
- **Eval:** fixture question scores citation coverage, source independence (distinct domains), and
  conflict detection.
- **Priority: high** — advances "smarter" and "research" at once; Rust + self-hosted search is a
  lightweight combo the Python competitors can't match.

## 4. More stable — resilience is now table stakes

- **Have:** stability board + SLO targets, eval gate, scheduler, full `Vec<Message>` persistence.
- **Signal:** OpenClaw 2026.6.1's headline was interrupted-tool-call recovery — resilience is the
  bar, not a bonus.
- **Do (raise Track C to parallel with v0.3.0):** interrupted-tool-call recovery and resumable
  long runs (transcript already persisted); scheduler **dead-letter queue + replay** (stability
  board P1); per-tool/MCP **timeout budget matrix**; finish the non-web progress heartbeat
  (`non-web-channel-progress-events-plan.md` Phase 3).
- **Eval:** kill-and-resume fixture continues a half-finished tool loop; DLQ replay restores a
  failed scheduled run.
- **Priority: high** (table stakes).

## 5. Security — two layers, both ours to take

### 5a. Harden MicroClaw itself (defensive posture — Track B)
- **Have:** `path_guard`, `web_fetch` SSRF guard, hash-chained audit (#418), Docker sandbox wired
  to `bash`, warn-only `GuardrailController`.
- **Do:** promote guardrails **warn → block** (pre-tool-call policy + post-output secret/PII scan);
  **native process-wide egress control** (Rust, fail-closed, in-process — the OpenClaw Proxyline
  pattern done better); per-chat/per-agent **least-privilege tool authorization** (OWASP Agentic
  Top 10); sandbox **credential hygiene** (sandboxed `bash` never sees real API keys).
- **Eval:** a blocked tool call and a redacted post-output are covered by fixtures.
- **Priority: high** — low-risk, pure-additive, reinforces the signature pitch.

### 5b. MicroClaw as a security-domain agent (a vertical we can own)
- **Have:** `osv_check` (queries osv.dev for vuln/malware advisories), sandboxed `bash`, scheduler.
- **Do:** end-to-end use cases — scheduled **dependency-vulnerability monitoring** (scan a repo's
  deps → push on new CVEs), CVE/advisory subscription + summarization, light log-anomaly triage,
  an incident-response helper. A **secure-by-default, auditable, self-hosted** agent is the natural
  trust base for security ops — you wouldn't hand security work to a bot that ships your data to a
  cloud.
- **Priority: medium** — validate demand by extending `osv_check` into the dependency-monitor case
  first.

---

## Sequence (folds into v0.3.0 finish → v0.4.0)

| # | Item | Axis | When | Risk |
|---|---|---|---|---|
| 1 | Pluggable search backends + `deep_research` | research/smarter | **shipped** | low |
| 2 | Skill curator (deterministic, skills-only) | smarter | v0.3.0 | medium |
| 3 | Guardrails warn→block + post-output scan | security 5a | v0.3.0 | medium |
| 4 | Resilience/recovery + scheduler DLQ replay | stable | v0.3.0→v0.4.0 | medium |
| 5 | Deep-research workflow (contract orchestration) | research | v0.4.0 | medium |
| 6 | Native egress control + per-chat tool authz | security 5a | v0.4.0 | high |
| 7 | Security vertical (dep-monitor / CVE summarize) | security 5b | v0.4.0 | medium |
| 8 | Personality growth / inner monologue | human | after eval coverage | high |

Guarantees unchanged: no default behavior change; new autonomous/isolation features off by
default; per-PR checklist (`cargo test -q`, web build, docs artifacts check, rollback note).
