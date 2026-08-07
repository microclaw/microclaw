# Competitive Intel Update — 2026-08-07

Status: **intel refresh** · Companion to
[`competitive-intel-update-2026-07.md`](./competitive-intel-update-2026-07.md) (2026-07-05)
and [`competitive-landscape-and-direction-2026-h2.md`](./competitive-landscape-and-direction-2026-h2.md) (2026-06-20)

A one-month delta pass on OpenClaw, Hermes Agent, and — promoted to a tracked competitor this
cycle — ZeroClaw, plus what it changes for MicroClaw's next steps. Confidence markers as before:
**[primary]** = official releases/repos/major press; **[secondary]** = blogs/aggregators.

The 06-20 thesis and adjustments A–G all **hold**. Notably, everything the 07-05 doc queued for
MicroClaw has since shipped: completion-contract verification via the `deep-research-workflow`
skill (v0.3.3, adj. E), user-directed learning via Learning Foundry (v0.3.4, adj. F), opt-in
`HEARTBEAT.md` proactivity and per-chat daily token budgets (adj. G + positioning bonus), plus
the durable delivery outbox and Reliability Proof Pack (v0.3.3). This pass adds four new
signals (H–K below).

---

## 1. What's new since 2026-07-05

### OpenClaw (`openclaw/openclaw`, CalVer)

- **Foundation launched (07-08) [primary/press]** — the long-promised governance landed: a
  501(c)(3) stewarded by Dave Morin and Peter Steinberger, with OpenAI, NVIDIA, Microsoft, and
  Tencent as sponsors; project stays MIT. Late-July discussion of **extended-stable (LTS)
  releases and a "maturity scorecard"** [secondary] — the enterprise-trust push is now
  institutional, not just talk.
- **v2026.7.1 stable [secondary, official docs unreachable through our proxy]** — session-first
  Control UI (searchable sidebar, context ring, reasoning-effort controls, generated titles,
  session groups); agent-loop onboarding; Claude Sonnet 5 / Mythos 5, Meta Muse Spark 1.1,
  ClawRouter; GPT-5.6 as new-setup default. Patch releases 2026.7.1-1/-2 (08-04) [primary].
- **v2026.7.2-beta series through beta.7 (08-02) [primary]** — the big one for our purposes:
  - **State safety**: quarantine store that survives primary-database damage, crash-recoverable
    SQLite snapshots, crash-durable filesystem publication;
  - **Channel delivery durability**: message recovery across restarts for
    Telegram/Signal/Slack/Discord/WhatsApp;
  - **Session branching**: rewind/fork conversations from individual messages;
  - **Structured approvals**: option cards across web and mobile;
  - Breadth continues too: MCP Apps, meeting bots (Teams/Zoom/Meet with durable transcripts),
    Wear OS companion, local inference (llama.cpp/Gemma), Claude Opus 5, Kimi K3, GPT Live.
  - Security: channel allowlist access control, session export boundaries, secret redaction
    hardening, approval ID validation.
- **Security climate [secondary]** — trackers now tally **~138 OpenClaw CVEs** for 2026;
  ClawHub supply-chain abuse (1,400+ malicious skills confirmed by April) remains the
  category's cautionary tale. Nothing new at the CVE-2026-32922 severity level this month.

### Hermes Agent (`NousResearch/hermes-agent`)

- **v0.19.0 "Quicksilver" (07-20) [primary]** — a *speed and trust* release (~2,245 commits,
  ~3,300 issues closed, 450+ contributors):
  - **~80% first-turn TTFT reduction** on every platform; desktop perf overhaul (14× faster
    markdown streaming); live-streamed reasoning by default — directly answers the "token
    overhead / sluggishness" criticism that was their loudest complaint in June;
  - **Delivery-obligation ledger** — finished responses survive gateway crashes;
  - **Smart approvals on by default** — an LLM independently reviews flagged commands;
  - Password-manager secret sources (Bitwarden/1Password), live subagent transcripts,
    mem0 recall-tuning dashboard, `max`/`ultra` reasoning tiers, in-terminal billing.
- **v0.19.1 (07-30) [primary]** — ~1,000-PR stable rollup for downstream consumers.

### ZeroClaw (`zeroclaw-labs/zeroclaw`) — promoted to tracked competitor

Previously covered only in the sandbox comparison (2026-03). Rust-native like MicroClaw, and
its cadence now warrants tracking [all primary, from GitHub releases]:

- **v0.8.2 (06-26)** — universal ingress policy layer (every inbound turn passes one SOP-backed
  policy layer), A2A agent discovery, durable SQLite-backed run/task control plane.
- **v0.8.3 (07-16)** — SOP engine with **typed step contracts**; **WASM plugin host on the
  wasmtime component model**; git-forge channel (GitHub/Gitea/Forgejo); task-attributed **cost
  ledger with offline pricing catalog**; Tauri desktop app.
- **v0.8.4 (08-02)** — memory retrieval caching + reranking, per-SOP admission policies,
  dashboard-driven upgrades, Mattermost channel.

### Convergent reading

**Durable delivery went from differentiator to table stakes in a single month.** OpenClaw
(state-safety betas), Hermes (delivery-obligation ledger), and MicroClaw (outbox, v0.3.0-0.3.3)
all shipped crash-surviving delivery within weeks of each other. The June trend — "can you
trust what it did" — has now consumed the reliability layer itself; the frontier moves to
*proving* it. Second convergence: **approvals are getting richer** — OpenClaw's option cards,
Hermes' LLM-judged smart approvals, ZeroClaw's admission policies. Third: **every leader now
has a sandboxed-ish plugin/skill story** (npm-with-scanning, skills, wasmtime WASM) and the
supply-chain pain is still OpenClaw's; RFC 0006's caution is validated, but ZeroClaw proves
WASM-component hosting is shippable in Rust.

---

## 2. Effect on the plan — new adjustments H–K

| # | Adjustment | Driven by | Effect |
|---|---|---|---|
| H | **Publish the reliability evidence.** The Reliability Proof Pack already runs in CI; surface it: a docs page + README link with the machine-readable scorecard per release, framed as "verified-durable delivery, recovery, and fail-closed sandbox — reproducible with one script." Competitors *claim* durability; MicroClaw can *show* the harness. | All three shipping durability claims [primary] | Low effort (docs/CI wiring only); converts an already-built asset into the differentiation the 2026-07 reliability roadmap wanted. |
| I | **Structured approvals v2.** Extend the existing `approval_required` flow (high-risk tool gate) with option-card-style structured prompts in web + control chat, and an *opt-in* aux-model risk reviewer (default off, per the no-default-change guarantee). | OpenClaw option cards, Hermes smart approvals [primary] | Medium effort; builds on existing risk/auth plumbing; keeps parity on the category's trust UX without ceding autonomy defaults. |
| J | **Plugin host: hold the RFC 0006 course, add a wasmtime spike.** ZeroClaw's component-model host is an existence proof in Rust; before committing to the supervised-stdio TS host, time-box a spike comparing capability mediation, cold-start, and build determinism against RFC 0006's design. Decision doc, not a pivot. | ZeroClaw v0.8.3 [primary] | Prevents locking in the weaker isolation story while the ecosystem consolidates on WASM components. |
| K | **Tokens-per-task benchmark — still open, now more urgent.** Hermes just cut TTFT 80% and neutralized much of its cost criticism; the "low token overhead on a $5 VPS" pitch needs published numbers before that window closes. Budgets + `insights` shipped; the measured comparison doc did not. | Hermes v0.19 [primary]; 07-05 positioning bonus | Carry-over; small, unblocking, high positioning value. |

**Watch-items:**
- OpenClaw LTS / maturity scorecard: if the Foundation formalizes a scorecard, map MicroClaw
  against it early — free credibility if we already pass.
- Session branching (OpenClaw beta) vs MicroClaw's shipped session fork (Phase 3): parity
  exists at the API level; consider exposing fork/rewind in chat commands, not just web.
- ZeroClaw's ingress policy layer overlaps MicroClaw's per-principal tool authorization;
  no action, but keep an eye on their per-SOP admission policies as prior art for scheduled
  task policy scoping.

### Explicit non-goals — reaffirmed

Meeting bots, wearables, voice, MoA model mixing, and 24-channel breadth remain non-goals; the
$5-VPS single-binary thesis is untouched. Local inference needs no work: llama.cpp servers
already speak the OpenAI-compatible protocol MicroClaw supports.

---

## 3. Updated sequence

v0.3.x closed out E/F/G. Proposed order for the next cycle:

1. **H — reliability scorecard publication** (docs + release wiring; days, not weeks).
2. **K — tokens-per-task benchmark doc** (measure against Hermes/OpenClaw on 3-5 canonical
   tasks; publish method + numbers).
3. **I — structured approvals v2** (web/control-chat option cards; opt-in aux-model reviewer).
4. **J — wasmtime spike + plugin-host decision doc** (gates any RFC 0006 implementation work).
5. Then the standing v0.4.0 remainder: contract-governed orchestration hardening and the
   TS-plugin-host build-out per the J decision.

Guarantees unchanged: no default behavior change; every autonomous/isolation-changing feature
off by default; per-PR checklist from `feature-completion-tracking-board.md` applies.

---

## 4. Sources

**OpenClaw [primary]:** github.com/openclaw/openclaw/releases (2026.7.2-beta.5–7, 2026.7.1-1/-2,
fetched directly) · trendingtopics.eu (Foundation launch w/ sponsor list).
**[secondary]:** explainx.ai (Foundation 501(c)(3)) · blog.mean.ceo (August ecosystem digest) ·
petronellatech.com · betterclaw.io (CVE tally) · sangfor.com (supply-chain retrospective) ·
gradually.ai + releases.sh + releasebot.io (v2026.7.1 stable details; sites proxy-blocked,
content via search snippets only — hence [secondary]).

**Hermes [primary]:** github.com/NousResearch/hermes-agent/releases v2026.7.20 + v2026.7.30
(fetched directly). **[secondary]:** hermes-ai.net/changelog · aiengineerinsights.com.

**ZeroClaw [primary]:** github.com/zeroclaw-labs/zeroclaw/releases v0.8.2–v0.8.4 (fetched
directly).

**Category [secondary]:** vellum.ai personal-assistant roundups (memory-as-table-stakes,
three-sub-category split) · aimagicx.com + shareuhack.com (alternatives comparisons).

*Caveat:* docs.openclaw.ai and several aggregators are blocked by our network egress proxy;
OpenClaw stable-release detail rests on search snippets cross-checked against the GitHub
releases feed. Earlier "ZeroClaw repo taken down (March)" reports are stale — the GitHub
releases feed shows continuous activity through 08-02.
