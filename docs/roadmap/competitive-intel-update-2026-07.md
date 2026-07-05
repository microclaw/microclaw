# Competitive Intel Update — 2026-07-05

Status: **intel refresh** · Companion to
[`competitive-landscape-and-direction-2026-h2.md`](./competitive-landscape-and-direction-2026-h2.md) (2026-06-20)
and [`v0.3.0-completion-and-v0.4.0-kickoff.md`](./v0.3.0-completion-and-v0.4.0-kickoff.md)

A two-week delta pass on OpenClaw and Hermes Agent since the 2026-06-20 landscape doc, plus what
it changes for MicroClaw's next steps. Confidence markers as before: **[primary]** = official
releases/repos/major press; **[secondary]** = blogs/aggregators. The 06-20 doc's thesis and its
four adjustments (A–D) all **hold**; this pass adds three new signals (E–G below).

---

## 1. What's new since 2026-06-20

### OpenClaw (`openclaw/openclaw`, CalVer)

- **v2026.6.11 stable (06-30) [primary]** — a *reliability* release: misrouted replies, stuck
  sends, and reconnect fixes across ~10 channels (Telegram/WhatsApp/Matrix/iMessage/Feishu/…);
  **Codex pairing + steering from Telegram** (`/login`) — first visible OpenAI-integration
  feature since the foundation move; **on-exit schedules** (wake agent when a watched command
  exits); new cron options; safer admin defaults; refreshed iOS app (Talk voice control);
  `openclaw attach` to hook an external harness onto a running Gateway session.
- **v2026.7.1-beta.1 (07-02) [primary]** — GPT-5.6 family across catalog/capability/runtime;
  `attach` expansion.
- **Direction [secondary]** — talk of an **LTS track**; development center of gravity is
  reliability + security (agent recovery, audit trails, MCP validation). Foundation governance
  docs still unpublished as of April — a community sore point.
- **Ecosystem [primary]** — NVIDIA **NemoClaw** enterprise distro (GTC, March) sells "OpenClaw
  minus the security problem"; ClawHub now scans with VirusTotal + ClawScan, yet new bypasses
  keep appearing (22 MB README padding to defeat scanner size caps, runtime affiliate-link
  injection). Supply-chain pressure is ongoing, not resolved.
- **Unchanged hallmark** — heartbeat proactivity (HEARTBEAT.md check-ins) is still the #1
  community-cited differentiator.

### Hermes Agent (`NousResearch/hermes-agent`, ~209k stars)

Three majors in four weeks [all primary, from official releases]:

- **v0.16 "Surface" (06-05)** — native desktop app (macOS/Linux/Windows), web admin dashboard,
  full Simplified-Chinese localization.
- **v0.17 "Reach" (06-19)** — iMessage without a Mac relay (Photon), WhatsApp Business Cloud
  API, background/async subagents with desktop observation windows.
- **v0.18 "Judgment" (07-01)** — the big one:
  - **~700 P0/P1 issues zeroed out** (same June reliability convergence as OpenClaw);
  - **Completion verification engine**: *completion contracts* + evidence-based checks, `/goal`
    command — "task done" now means *verified done*;
  - **`/learn`**: user-triggered distillation of a reusable skill from a directory, URL, or
    completed workflow; **`/journey`**: memory/skill growth timeline;
  - Mixture-of-Agents as a selectable "model"; background fan-out subagents; desktop
    git-worktree project management; gateway scale-to-zero; Vertex AI.
- **Top community criticism [secondary, multi-source]** — token overhead: memory/context
  injection grows with use ("week-3 bill problem"); aux-model timeouts cascade into
  compaction/memory failures. Also: ops burden, doc lag behind release pace.
- Ships an official **OpenClaw migration tool**; security record still clean (no public CVEs).

### Convergent reading

June was the month both leaders **stopped shipping breadth and shipped trust**: OpenClaw's
biggest stable was delivery/reconnect fixes; Hermes zeroed its P0/P1 backlog. The category's new
headline is shifting from "what the agent can do" to **"can you trust what it did"** — Hermes'
completion contracts are the first mover on runtime verification.

---

## 2. Effect on the plan — adjustments A–D confirmed, E–G added

The 06-20 adjustments stand: **A** egress-control headline, **B** resilience as table stakes
(MicroClaw already shipped scheduler DLQ auto-replay + provider fallback in #450 and the
post-output credential guardrail in #443 — ahead of schedule on B and half of P5b), **C**
contract-governed orchestration, **D** no self-evolution. New:

| # | Adjustment | Driven by | Effect |
|---|---|---|---|
| E | **Add completion-contract verification to the orchestration line item.** Each declared sub-task carries an exit contract; fan-in checks evidence, not vibes. Builds directly on the `submit_result` structured-output tool (#450) and the offline eval gate. | Hermes v0.18 `/goal` [primary] | Extends v0.4.0 item C; low-medium effort, hits the category's emerging trust theme. |
| F | **Ship the skill curator's first slice as a user-triggered `/learn`-style command**, not a background loop. Same pipeline (draft → ClawHub `gate.rs` scan → created *disabled* → control-chat approval), but user-invoked distillation from a completed session. Background curation becomes phase 2. | Hermes `/learn` [primary]; approval-gated consensus | De-risks P2 and delivers the "gets better the longer it runs" pitch sooner. |
| G | **Opt-in heartbeat proactivity** (default off): a scheduler-driven periodic check-in that reads a per-chat `HEARTBEAT.md` task list and decides whether to act/message. All plumbing exists (scheduler + `override_prompt` + `process_with_agent`). | OpenClaw's #1 cited differentiator [primary] | Small, cheap, closes the one hallmark gap; respects the no-default-change guarantee. |

**Positioning bonus (cheap, non-blocking):** Hermes' loudest complaint is token cost. MicroClaw
already has the `insights` usage tool, aux-model slots, and compaction. Add per-chat **token
budget caps** and publish a measured tokens-per-task comparison in docs — "low token overhead"
becomes a stated, benchmarked property of the $5-VPS pitch rather than an implication.

**Security watch-items (from OpenClaw's ongoing pain):**
- Audit the web UI for any `gatewayUrl`-class trust of query-string-supplied endpoints
  (CVE-2026-25253 pattern).
- Harden ClawHub `gate.rs` against scanner-bypass patterns seen in the wild: content-size
  padding, runtime (post-install) payload mutation.

---

## 3. Updated sequence

**v0.3.0 finish (reordered per F):**
1. `/learn`-style user-triggered skill distillation (P2 slice 1) → background curator (slice 2).
2. Pre-tool-call **blocking** policy (P5b remainder — post-output scan shipped in #443).
3. Sandbox credential hygiene (P4c), then gVisor/SSH backends.

**v0.4.0 (adjusted):**
4. Native egress control (headline, unchanged).
5. Per-chat / per-agent least-privilege tool authorization (unchanged).
6. Resilience remainder: interrupted-tool-call recovery + non-web progress heartbeat
   (DLQ replay ✅ shipped #450).
7. Contract-governed orchestration **with completion-contract verification** (C+E).
8. Opt-in heartbeat proactivity (G) + token budget caps — small items, schedule opportunistically.

Guarantees unchanged: no default behavior change; every autonomous/isolation-changing feature
off by default; per-PR checklist from `feature-completion-tracking-board.md` applies.

---

## 4. Sources

**OpenClaw [primary]:** github.com/openclaw/openclaw · docs.openclaw.ai/releases/2026.6.11 ·
thehackernews.com (CVE-2026-25253) · unit42.paloaltonetworks.com (ClawHavoc follow-ups) ·
nvidianews.nvidia.com/news/nvidia-announces-nemoclaw · techcrunch.com 2026-03-16.
**[secondary]:** smartproductivitytools.com (LTS talk) · cloudbees.com (governance critique) ·
releasebot.io.

**Hermes [primary]:** github.com/NousResearch/hermes-agent/releases (v0.16/0.17/0.18, fetched
directly) · marktechpost.com 2026-06-03. **[secondary]:** innfactory.ai · composio.dev ·
xda-developers.com · 36kr.com · hermes-agent.ai/blog (token overhead).

*Caveat:* several official pages were only reachable via search snippets (proxy 403s); release
content was verified against GitHub release pages where possible. SEO content-farm claims
(e.g. "OpenClaw v4.0") were identified and discarded.
