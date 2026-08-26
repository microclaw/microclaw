# Changelog

All notable changes to this project should be recorded in this file.

The format is loosely based on Keep a Changelog. Dates use UTC.

## Unreleased

### Added

- **Linux Work launch gate.** Extended CI now starts the release GPUI desktop
  under Xvfb with Mesa Vulkan support and requires the process to remain alive,
  complementing the existing Linux compile, test, Clippy, and preview artifact
  checks without overstating it as physical GPU coverage.
- **Native MicroClaw Work Windows installer.** A dedicated Inno Setup package
  now installs the GPUI desktop per user with the website brand icon, Start menu
  entry, optional desktop shortcut, and clean uninstall. Its build path can
  Authenticode-sign and verify both the application and installer; Windows CI
  builds the unsigned preview, silently installs it, launch-smokes the packaged
  application, uninstalls it, and publishes the resulting setup executable.
- **Branded macOS Work installer preview.** The native bundle now derives its
  complete `.icns` set from the same blue MicroClaw logo used by the website.
  New packaging and launch-smoke scripts create and verify a DMG, ad-hoc sign
  development previews, or enable Hardened Runtime and trusted timestamps for
  a supplied Developer ID identity. Extended CI now publishes the DMG preview
  and proves the packaged application stays alive after launch.
- **Agent Engine first-response proof.** Work Diagnostics can now run a fixed,
  explicit end-to-end probe through provider streaming, the shared Agent
  Engine, durable runtime assembly, versioned Work events, and visible final
  completion. Results are bounded and secret-redacted.
- **Refined native Work presentation.** The GPUI desktop now uses a quieter
  layered sidebar, a distinct active-conversation card, contextual status
  colors, polished chat bubbles and composer surfaces, starter prompts, and
  structured diagnostic cards with compact state badges.
- **Native Work diagnostics.** The desktop now exposes an offline diagnostics
  report for model configuration, active-workspace writes, durable conversation
  storage, and credential-file permissions, with an explicit redacted provider
  connection probe beside the local checks.
- **Direct-to-chat MicroClaw Work onboarding.** New desktop installations now
  provision a private platform-local Work Home, surface model configuration in
  the empty chat canvas, and allow the first conversation without forcing the
  user through a project-folder picker. Missing external projects safely fall
  back to Work Home.
- **Cross-platform Work preview gate.** Extended CI now compiles and tests the
  shared Work session/runtime/recovery path on Linux, macOS, and Windows, builds
  the native GPUI desktop in release mode on every platform, and uploads
  short-lived Linux, macOS, and Windows preview archives. The Linux job installs
  the native dependencies required by the repository's pinned GPUI/Zed revision.
- **Chat-first MicroClaw Work home.** The GPUI desktop now opens into a
  conversation workspace instead of a task dashboard: New Chat and durable
  conversation history lead the sidebar, setup state is compact and secondary,
  the empty thread has a dedicated welcome state, user messages align as chat,
  and a larger persistent composer carries folder and model context. Plan,
  process evidence, and change review live in a collapsible Details inspector
  so ordinary conversation can use the full canvas.
- **Conversation-first MicroClaw Work shell.** The native desktop now treats
  each task as a durable conversation: user and assistant messages are stored
  in the Work snapshot, streaming text is coalesced into an assistant draft,
  and the composer stays at the bottom of the primary chat surface. Plans,
  approvals, process evidence, and artifacts remain supporting work context.
- **Continuous Work threads.** Submitted turns and unsent composer drafts now
  have separate durable state. Sending clears the bottom composer, completed
  tasks accept direct same-session follow-ups without deleting prior messages,
  and approval choices appear inline in the conversation where execution
  pauses instead of living in a separate empty inspector card.
- **Native multi-file change review.** Work snapshot schema v13 persists the
  selected changed file. The inspector now provides an explicit multi-file
  list, addition/removal and truncation metadata, a bounded scrollable unified
  diff with added/removed line highlighting, safe file opening, and the
  existing accept/revert decision in one review surface.
- **Provider connection diagnostics.** Model Settings now stays open after a
  save and offers an asynchronous Test Connection action. The shared Work
  runtime sends a minimal provider request with a 20-second bound, verifies
  endpoint/auth/model/response handling, reports latency and a bounded response
  preview, and redacts the configured credential from errors.
- **Retryable recovered Work threads.** Interrupted, failed, and cancelled
  runs now use a first-class Retry command that reuses the last submitted turn
  even when the composer is empty. Retry preserves the conversation without a
  duplicate user message and clears stale partial-run plans, drafts, activities,
  diffs, approvals, and review state before starting again.
- **Process-level Work recovery harness.** The no-GPUI executable can now abort
  after persisting a partially streamed Running session, recover it in a second
  process, and retry it in a third. An integration test proves stable session
  identity, transcript preservation, Interrupted projection, and stale-run
  cleanup across real operating-system process boundaries.

- **MicroClaw Work post-task review.** Foreground Work runs emit a pre-task
  checkpoint and completed file changes can be accepted, continued in the same
  runtime session, or reverted through a native confirmation and background
  shadow-git restore. Empty workspaces, later tracked files, and new unignored
  files are restored correctly while ignored secrets and nested repositories
  remain protected.
- **Live native Work plans.** Successful shared `todo_write` calls now emit a
  provider-neutral structured plan event. The GPUI desktop projects pending,
  active, and completed steps durably and no longer invents a fixed four-step
  plan before the Agent has planned the task.
- **In-run Work steering.** The native composer switches to `Send Update` while
  a foreground task is active. Guidance enters the existing Agent Engine
  mid-turn queue, is acknowledged only when the active session accepts it, and
  remains visible in the durable Work timeline.
- **Structured native approvals.** Runtime Event v5 gives every approval choice
  an explicit response value, Approve/Deny decision, and visual intent. Work
  persists the complete approval card, renders advisory text and native choice
  buttons, and resumes the same Agent session with the selected value.
- **Native verification evidence.** Runtime Event v6 exposes bounded, redacted
  Bash output with command, exit code, duration, truncation state, and command
  or verification classification. Work persists this evidence and renders it
  in a scrollable native Process Output panel.

## 0.5.0 - 2026-08-16

### Added

- **Plan mode.** `/plan` (or the ACP `plan` session mode) restricts the agent
  loop to read-only tools and presents a plan; an approving reply re-runs the
  work with the full toolset.
- **Headless one-shot CLI.** `microclaw run -p "<prompt>" [--session <name>]
  [--json]` runs a single prompt with no channels attached.
- **API-key pool rotation.** `api_keys` (top-level or per provider profile)
  forms a round-robin pool that rotates on 401/403/429 responses.
- **Per-chat model and provider overrides.** `/model here <name>` and
  `/provider here <alias>` scope an override to one chat.
- **Context-pressure compaction.** Mid-turn compaction triggers at
  `context_pressure_compact_pct` of `model_context_window`, with
  compact-and-retry on provider context-overflow errors. The compaction split
  is tool-block aware.
- **Interactive approval buttons.** High-risk approval option cards render as
  native buttons on Telegram, Discord, Slack, and web; a tap re-enters the
  existing text approval-parsing path.
- **`AfterTurn` hook event and opt-in self-recheck.** `self_recheck.enabled`
  adds a one-pass post-edit review before finalizing.
- **File-edit diffs and progress reporting.** `edit_file`/`write_file` attach a
  unified diff to tool metadata, forwarded to web SSE and to chat behind
  `file_diffs_in_chat`. Non-web channels gained a throttled edit-in-place
  progress heartbeat with a percent bar, live sub-agent count, and optional
  message pinning.
- **Reply-quote forwarding.** Replying to an earlier message prepends
  `[quoted from <author>: …]` on Telegram, Discord, and Weixin.
- **Group-concise soul preset.** `examples/soul/group-concise.md` tunes replies
  for busy group chats.

### Changed

- **Website and README refresh.** The public homepage now highlights the current
  release, project descriptions and skill counts match the v0.5.0 runtime, the
  roadmap is recast as durable project direction, and obsolete Docusaurus
  starter assets and internal iteration pages are removed.

- **Monolith source files decomposed.** The five remaining oversized files
  are split into domain modules behind unchanged import paths: `src/llm.rs`
  (5,280 lines -> provider/translation/resilience modules), `src/setup.rs`
  (11,276 -> eleven wizard modules), `src/web.rs` (6,775 -> state/dto/route
  modules alongside the existing submodules), `src/config.rs` (5,387 -> eight
  config domains), and `db/learning.rs` (6,923 -> experience/skills/tracks).
  All moves are verbatim with pub(crate) visibility promotions only; test
  counts are unchanged.
- **Storage layer decomposed.** `crates/microclaw-storage/src/db.rs` (17,178
  lines, 237 public methods in one `impl` block) is split into 14 domain
  modules under `db/` (chats, sessions, tasks, subagents, memory, learning,
  usage, auth, audit, outbox, turns, tool cache, runtime meta, schema) behind
  the unchanged `Database` facade. All moves are verbatim; public API,
  migration history, and test counts are identical, and no consumer code
  changed.
- **Web UI build moved to vite 8 and React 19**, closing the remaining
  build-tooling advisories (vite path traversal, esbuild dev-server origin).
  The bundle is now split into `react`, `markdown`, and `vendor` chunks instead
  of one ~957 kB file, so the assets embedded in the binary cache
  independently.
- **Web UI frontend decomposed.** `web/src/main.tsx` (4,927 lines, 61% of the
  frontend) is split into `lib/` modules (think-tag extraction, backend types,
  config model, session helpers, SSE parsing) and per-concern components
  (chat thread, config controls, all settings tabs); `main.tsx` is now 2,373
  lines with identical behavior, verified end-to-end against a running
  backend.
- **Docs site dark theme rebuilt for contrast.** The page, section, and card
  tones previously sat within ~5% lightness with card shadows disabled, which
  read as one flat grey field; they now form a deliberate lightness ladder with
  visible card edges. Site default color mode is `light` (an explicit OS
  preference still wins).
- **Web operator UI visual system refreshed.** The embedded console now uses a
  consistent surface, border, type, and elevation system across dark, light,
  and accent themes. The session sidebar, active-session state, runtime header,
  settings navigation, dialogs, forms, and mobile layout have clearer visual
  hierarchy without changing their behavior or API contracts.

### Fixed

- **A clean clone now builds on Node 22 LTS.** `web/package.json` pinned
  `engines.node` to `24.x` while `web/.npmrc` sets `engine-strict=true`, so the
  unconditional `npm ci` in `build.rs` aborted `cargo build` on any other Node
  major — including in `snap/snapcraft.yaml`, which pulls `node/22/stable` and
  therefore could not build the snap at all. The pin is now `>=22`.
- **`check.sh` no longer passes silently on failure.** It had no `set -e`, so it
  ran past failing steps and exited with the last command's status. It also
  still invoked `npm --prefix website`, left over from the `website/` → `site/`
  move, as did `deploy.sh` and five release checklists.
- **CI now builds the web UI and docs site on both supported Node LTS majors**,
  the gap that hid the `engines` break.

## 0.4.0 - 2026-08-07

### Added

- **Web approval option cards.** The web chat renders a paused high-risk
  approval as clickable option buttons (approve once / always allow / deny)
  driven by the structured `approval_required` stream event; clicking sends
  the same numbered reply the text contract defines.
- **Reliability scorecard publication.** Every release attaches
  `reliability-scorecard-<tag>.{json,md}` (the proof-pack results generated
  from the tagged source) to its GitHub release assets; CI uploads the same
  scorecard per push, and a docs page covers scope, schema, and one-script
  reproduction.
- **ClawHub load-time integrity verification.** Managed skills are
  re-verified against their lockfile tree hash whenever skills load.
  `clawhub_verify_on_load` (default `block`) hides tampered skills and fails
  activation with an actionable message; unpinned pre-hash installs warn
  instead of blocking.
- **Consolidated status surface.** `/status` and the web governance
  snapshot/panel report scheduler DLQ depth, 24h contract verdicts,
  token-budget usage, provider failover/circuit-breaker health, and
  supervised-loop restart counters.
- **Opt-in webhook alerts.** A supervised loop POSTs JSON alerts on DLQ
  growth, provider down, budget exhaustion, and restart storms — baseline
  first poll, per-class cooldowns, egress-governed webhook, audit-chained
  deliveries. Off by default.
- **Opt-in periodic trust report.** A digest of task runs, contract
  verdicts, token spend, guardrail audit events, and reliability health
  delivered to control chats on a restart-surviving cadence. No LLM calls;
  off by default.
- **Structured approvals.** High-risk approval prompts are numbered option
  cards (approve once / always allow in this chat / deny) with en/zh
  keywords; "always" records an audit-chained standing per-chat grant
  managed via the new `/approvals` command, and web clients receive a
  structured `approval_required` stream event. An opt-in
  `aux_models.approval_reviewer` annotates prompts with an advisory verdict
  and never decides.
- **MCP/A2A trust tiers.** Per-server (`trust: trusted|limited|sandboxed`
  in `mcp.json`) and per-peer (`a2a.peers.<name>.trust`) tiers map onto
  tool-policy risk; omitted = `limited` = historical behavior, `sandboxed`
  requires explicit approval.
- **Model-swap canary.** `microclaw canary <model>` probes a candidate
  model (response + tool-calling) through the exact configured provider
  path before an operator switches `model:`.
- **User message language.** `user_message_language` (`en` default / `zh` /
  `bilingual`) selects the language of approval prompts and token-budget
  refusals via a new message catalog.
- Plugin-host runtime decision recorded as RFC 0007 (hold RFC 0006's
  supervised Node host; reserve wasmtime for a future compute-skill
  surface), plus an OWASP agentic top-10 self-assessment and a published
  tokens-per-task benchmark method with extraction script.

### Changed

- Replaced the green MicroClaw identity with a blue cyber-claw mark across
  repository and documentation-site assets, and refreshed the public site's
  palette, typography, cards, controls, favicons, PWA icons, and social card.
- Reworked the root README files into concise project entry points, moved
  setup and integration detail into task-focused documentation, and added
  localized overview and quick-start pages for 10 widely used languages.

## 0.3.5 - 2026-08-01

### Changed

- Dependency maintenance now checks Cargo and Web npm updates weekly after a
  seven-day cooldown, keeps GitHub Actions on a predictable monthly schedule,
  and splits large update groups by SemVer level or dependency type. Web UI,
  CI, nightly, and release builds now require Node.js 24.x and enforce package
  engine compatibility during npm installs.

## 0.3.4 - 2026-07-31

### Added

- **Learning Foundry.** Durable user-directed learning tracks run bounded,
  read-only research epochs on a cron schedule and produce source-backed,
  test-bearing skill candidates. Candidates remain inert until an
  administrator explicitly promotes them; existing skills continue to require
  comparative reflection and shadow evidence for changes.
- **Learning Foundry evaluator.** New candidates run paired no-tool
  baseline/candidate scenarios, persist token use, latency, evidence and
  regressions, and fail closed unless evaluation improves on baseline before
  manual promotion.

## 0.3.3 - 2026-07-30

### Added

- **Reliability Proof Pack.** `scripts/ci/reliability_scorecard.sh` now exercises
  recovery, scheduler replay, durable delivery, payload integrity, rate-limit
  recovery, command timeout, malformed provider wrappers, output sanitization,
  cross-chat permissions, and sandbox fail-closed behavior. It emits a
  machine-readable JSON scorecard, a linked Markdown report, and per-scenario
  logs; the existing Stability Smoke release gate runs the proof pack.
- **Contract-governed deep research workflow.** The new built-in
  `deep-research-workflow` skill decomposes broad questions into distinct
  parallel research packages, requires source ledgers and completion
  contracts, runs an adversarial verifier, and reports citation coverage,
  source independence, conflict disposition, unsupported claims, and a final
  PASS/FAIL verdict before synthesis.

### Fixed

- Database schema v41 repairs incomplete historical `scheduled_tasks`
  migrations even when `db_meta.schema_version` was already advanced. Existing
  databases missing `exit_criteria`, `run_count`, `max_runs`, `not_after`, or
  `timezone` are repaired on open before scheduler queries execute.

## 0.3.2 - 2026-07-28

### Added

- **Comparative reflection and governed skill evolution.** Comparable
  success/failure runs now produce versioned, counterexample-bearing learning
  claims and immutable candidate skill patches. Paired shadow observations
  gate promotion using risk-adjusted utility, cost, and regression thresholds;
  promoted candidates automatically roll back to the previous trusted version
  on verified regression. Web and CLI Learning Journals expose evidence,
  impact scope, evaluation state, and undo actions.
- **Failure-aware retrieval and skill recovery.** Verified failures and active
  task-scoped skill contraindications are excluded from prompt injection while
  their rejection reasons remain visible in the Learning Journal. Structured
  failure patterns track environment, tool, error category, cooldown, recovery
  trials, and automatic resolution from verified successes.
- **Task-signature and risk-adjusted skill evaluation.** Experience runs now
  carry a deterministic v1 task type, task family, capability tags, and stable
  signature hash, with schema-v38 backfill for existing history. Skill quality
  is aggregated overall and per task family with a configurable Wilson lower
  bound. Trial promotion requires both raw success and conservative utility;
  applicability and verified-experience retrieval now incorporate task
  compatibility, capability overlap, and utility rather than relying only on
  text and environment matches.
- **Verified long-horizon learning substrate.** Agent turns now produce durable
  goal, experience-run, verifier-evidence, skill-version, and attributed
  skill-outcome records. Governed skills progress through
  `candidate -> trial -> trusted`, degrade on verified regressions, can be rolled
  back to a recorded version, and are blocked when repeated failures establish
  an environment-specific contraindication. `/usage` and Web learning APIs
  expose the evidence and lifecycle; users can attach human feedback to a run.
  Experience records also capture token, model-request, tool, error, duration,
  and estimated-cost metrics. Strongly verified prior runs are recalled for
  similar tasks as untrusted historical evidence. Multiple human reviews are
  confidence-aggregated, expiring evidence is excluded, ambiguous multi-skill
  credit cannot govern skills, and an admin-scoped policy controls promotion
  and degradation thresholds. All evidence producers now enter through a
  versioned outcome envelope, human corrections have a normalized
  `experience_feedback` projection, and retrieval audit logs identify every
  prior experience injected into a run. `/learning [run_id]` and the
  run-detail Web API expose the experiences used, activated skills, and
  supporting evidence for an individual run.
- **Durable coworker checkpoints.** Interactive agent turns now persist
  provider-neutral message snapshots at safe model/tool-result boundaries. Fresh safe
  checkpoints resume automatically after restart; interruptions during tool execution
  stop with progress/tool evidence and never blindly replay an uncertain side effect.
  `/status`, Web Governance, and `turn_recovery` audit events expose the lifecycle.
- **Scoped secure-runtime policy.** Tool authorization can now apply least-privilege
  grants by chat, channel, and principal (main, scheduler, channel, or subagent), with
  global policy blocks remaining authoritative. A central egress policy validates
  configured endpoints and tool-input HTTP(S) destinations, including private/metadata
  address blocking and host allow/deny lists.
- **Sandbox credential isolation.** Dotenv files are no longer forwarded wholesale to
  containers. Credential-like variables are withheld by default and require an exact
  `sandbox.credential_env_allowlist` entry. Doctor/config self-check and Web Governance
  expose the new capability, egress, and credential posture.
- Added RFC 0006 for TypeScript-authored plugins: deterministic locked builds,
  supervised stdio JSON-RPC host, per-plugin principals, mediated filesystem/network/
  secret APIs, container isolation, and a phased SDK/runtime/distribution plan.
- Added `scripts/trigger_release.ps1` so Windows operators can validate and trigger the audited
  tag plus native Windows, macOS, Linux, checksum, and container release workflows with one command.
- Added the equivalent `scripts/trigger_release.sh` entry point for macOS and Linux release operators.
- **Durable chunk-level outbound delivery.** User-visible channel messages are now persisted before
  the first network call and tracked as independently retryable chunks. Interrupted sends resume
  from the unfinished chunk after restart, the full logical reply is stored exactly once, and
  Weixin reuses a stable native `client_id` for safe retries. Scheduler runs distinguish immediate
  delivery from durable queued acceptance instead of duplicating the full message in the outbox.
- **Shared user-visible output sanitization.** Final channel delivery strips private reasoning tags
  and textual tool-call traces at the common delivery boundary, including scheduler and tool-driven
  messages, so runtime protocol details do not leak into Weixin or other chat channels.
- **`microclaw doctor delivery`.** A read-only diagnostic now reports durable-ledger totals,
  unfinished chunks, retry state, oldest unfinished work, and terminal delivery failures without
  sending a test message or exposing credentials.
- Long channel replies now preserve newline bytes at chunk boundaries, so concatenating delivered
  chunks reconstructs the sanitized logical reply exactly instead of losing one newline per split.

- **Output guardrail (credential leak protection).** A new `output_guardrail` config block
  (`mode: off | redact | block`, default **off**) scans outbound bot messages for credential-like
  strings (OpenAI/Anthropic keys, GitHub PATs, AWS keys, Slack/Google tokens, Bearer tokens, PEM
  private-key blocks, `api_key=` assignments) before they are delivered. `redact` masks the secret
  and still delivers; `block` withholds the message. Applied both to each channel's main reply and
  to the shared tool/scheduler delivery path, so a secret echoed from tool output, memory, or the
  model can't leak to a chat. Detection reuses `microclaw-core`'s `redact` module, split so the
  outbound path strips **credentials only** (emails/phone numbers the bot legitimately sends are
  left intact). Every trip is logged to the `output_guardrail` trace target.
- **Pluggable web-search backends.** `web_search` (and the new `deep_research` tool) can now run
  against DuckDuckGo (default, no key), a self-hosted **SearXNG** instance, **Brave Search**, or
  **Tavily** — selected via the new `web_search` config block (`backend`, `searxng_base_url`,
  `brave_api_key`, `tavily_api_key`, `max_results`). Defaults preserve the historical DuckDuckGo
  behavior exactly, and a backend selected without its credentials/endpoint transparently
  degrades to DuckDuckGo instead of failing.
- **`deep_research` tool** — a deterministic multi-source research pass: fans out several
  sub-queries across the configured search backend, deduplicates sources, concurrently fetches the
  top pages through the existing SSRF-guarded `web_fetch` path, and returns a citation-numbered
  evidence digest with source-agreement signals (corroboration across sub-queries, coverage gaps).
  Semantic cross-verification and synthesis are left to the agent reading the digest, so the tool
  runs no LLM and is fully deterministic. Available to the main agent and to research sub-agents.

### Changed

- Clearer channel auth-failure logs — when a channel can't start because its credentials are
  rejected, Telegram/Discord/Slack/Feishu now log an actionable message ("authentication
  failed … check the token / run `microclaw setup`") instead of a generic or silent error,
  so a bad token isn't mistaken for the bot just going quiet. Part of the usability push.

### Fixed

- Built-in skill frontmatter now parses consistently from LF and CRLF checkouts, so
  platform and dependency gates no longer install incompatible skills on Windows.
- Release verification tests now use platform-native commands, paths, and symlink
  capabilities across Windows and Unix hosts.

### Added

- More guidance in the CLI: after `microclaw setup` succeeds it now prints the next steps
  (`microclaw doctor` → `microclaw start`, with a note about `doctor --online`); and
  `microclaw eval --help`, `microclaw audit --help`, and `microclaw doctor --help` each end
  with an Examples section. (`doctor --help` now routes to the doctor parser so its options and
  examples actually show.) Part of the usability push.
- Setup wizard now labels every field `[required]` or `[optional]` (previously only required
  fields were marked, leaving "unmarked" ambiguous), so it's obvious at a glance what must be
  filled before saving. Part of the usability push.
- `microclaw --help` now ends with an **Examples** section (setup, doctor, `doctor --online`,
  start, `skill audit`, `audit verify`, `eval`) and a pointer to per-command `--help`, so the
  common workflows are discoverable without reading docs. Part of the usability push.
- `microclaw doctor` now checks that the data and working directories can be created and
  written to — the most common "won't start" cause (read-only path, wrong permissions, a
  typo'd `data_dir`). Reports each as ✅ writable or ❌ with the failure reason and a fix hint.
  Part of the usability push.
- Setup wizard now refuses to save a config with no channel enabled — the source-side fix for
  "configured a channel but forgot `enabled: true`". Clearing all channels blocks save with a
  clear instruction instead of producing a config that fails to start. (The field defaults to
  `web`, so a normal setup is unaffected.) Part of the usability push.
- `microclaw doctor --online` — verifies the LLM credentials by sending a minimal "hi" request
  to the configured provider (reusing the setup wizard's probe), so a bad API key or model is
  caught at preflight instead of surfacing as a confusing failure on the first chat. Rejected
  credentials are a ❌ FAIL with a fix hint; a network/transient failure is a ⚠️ WARN (so an
  offline run isn't falsely red); `openai-codex` is skipped (external auth). Without `--online`,
  `doctor` stays hermetic and notes that credentials weren't verified. Part of the usability push.
- Clearer "no channel enabled" diagnostics — the common trap of filling in a channel's
  credentials but forgetting `enabled: true` now produces an actionable message instead of a
  generic one: the config error (and `microclaw start`) name the configured-but-disabled
  channels and tell you to set `channels.<name>.enabled: true`. `microclaw doctor` now (a)
  actually loads & validates the config (previously it only checked the file exists, so an
  invalid config showed a misleading green), and (b) reports which channels are enabled plus
  warns about any configured-but-disabled ones. Part of the usability/onboarding push.
- Friendlier config parse errors — when `microclaw.config.yaml` fails to parse, the message now
  appends an actionable pointer (edit and re-run, or `microclaw setup`, plus a link to the
  annotated example config), and for an unknown field/variant (a mistyped key like `discrod`)
  it suggests the closest valid name ("did you mean `discord`?"). The original serde error
  with its line/column is preserved. Part of the usability/onboarding push.
- In-chat `/help` command (aliases `/commands`, `/?`) — lists every slash command with a
  one-line description, grouped by area (session & context, model & provider, skills,
  memory & usage). There was previously no way to discover the 15+ commands from inside a
  chat. The CLI quick-start (`microclaw --help`) now points new users to it. First of a
  usability/onboarding push.
- Per-task auxiliary models: a new `aux_models` config section lets a (typically
  cheaper) model handle ancillary work. Wired slots:
  - `aux_models.compaction` — context/history summarization.
  - `aux_models.reflector` — the background memory reflector (fact/triple extraction),
    which runs periodically per active chat.
  - `aux_models.title` — one-shot session-title generation.
  - `aux_models.vision` — image description (the `describe_image` tool); overrides
    `media.vision.model` when set, and an explicit per-call `model` argument still wins.

  (`session_search` has no LLM step — it is pure full-text search — so it has no slot.)
- Tamper-evident audit log — every new `audit_logs` entry is now sealed into a SHA-256
  hash chain (`entry_hash` over the entry's fields plus the previous entry's `entry_hash`,
  with a genesis link for the first). Modifying a field, deleting a row, or reordering rows
  breaks the chain. A new `microclaw audit verify` command walks the chain and reports the
  first broken link (exiting non-zero so it can gate monitoring/CI), and `microclaw audit
  list [--kind] [--limit]` prints recent entries. Sealing happens under the DB connection
  lock so concurrent writers can't race the chain; pre-migration rows stay unsealed and are
  simply excluded from verification. First slice of the v0.4.0 security-governance track
  (tamper-evident audit).

  Each auxiliary model reuses the main provider profile and credentials — only the
  model name is swapped — and falls back to the main model when unset, so default
  behavior is unchanged. First steps toward the v0.3.0 "Self-Improving Runtime" plan
  (`docs/roadmap/v0.3.0-self-improving-runtime.md`).
- Sleep-time memory consolidation (`sleep_time`, off by default) — when a chat has been
  idle for a while, a background loop runs a deterministic (no-LLM) pass that archives
  near-duplicate same-category memories, so the store stops accumulating redundancy
  between reflector runs. PROFILE (identity) memories are never touched, archiving is
  reversible, and the pass is throttled per chat (`min_interval_hours`) and capped
  (`max_archived_per_pass`). First slice of the v0.3.0 sleep-time consolidation (Pillar 1c).
- `microclaw eval` subcommand — a deterministic trajectory-evaluation gate for recorded
  agent sessions, with no LLM call. It replays a session fixture (a JSON array of
  messages, or an object with a `messages` array) and checks trajectory health:
  no dangling `tool_use`, no orphaned `tool_result`, the session ends on a real answer
  (not a raw `tool_result`), tool-call count within `--max-tool-calls`, and tool errors
  surfaced (failing only under `--strict-tool-errors`). It also flags **stuck loops**
  (the same tool + arguments repeated `--max-repeats` times) and **consecutive
  tool-error streaks** (`--max-error-streak`). Accepts a file or a directory of
  fixtures, supports `--json`, and exits non-zero on failure so it can gate CI. Sample
  fixtures and usage in `docs/test/eval-fixtures/`. First slice of the v0.3.0 evaluation
  gate (Pillar 5). Enforced in CI via a "Trajectory eval gate" step that runs the
  passing fixtures in `docs/test/eval-fixtures/` (negative examples live in
  `docs/test/eval-fixtures/negative/`).
- `microclaw skill audit` subcommand — a deterministic, read-only curation view over the
  local skill corpus (no LLM, no DB, no mutation). `skill_review` distills a skill from a
  single session and the reflector retires skills purely by inactivity age; neither gives a
  cross-skill picture. The audit surfaces the signals a curator needs: **near-duplicate**
  skills (token-Jaccard over name + description — merge candidates, and a retire signal when
  an `agent-created` skill shadows a built-in), **stale** `agent-created` skills (old/absent
  `updated_at`), **thin** `agent-created` skills (near-empty body), and **cap headroom**
  against the `agent-created` ceiling. Built-in/human-curated skills are never flagged for
  retirement (they stay immutable) but still participate in duplicate detection. Accepts an
  optional directory argument (defaults to the configured skills dir), supports `--json`,
  and `--strict` exits non-zero when anything actionable is found, so it can gate CI. First
  slice of the v0.3.0 skill curator (Pillar 2).

## 0.2.0 - 2026-06-01

Milestone release consolidating everything since the 0.1.12 maturity-hardening
baseline: a concurrent specialist team, humanlike behavior, graph-augmented
memory, mid-turn interactivity, a multimedia tool suite, more channels, and
hardened packaging/release automation.

### Added

#### Agent capabilities

- Concurrent specialist team with 30 factory-ready skills and a more human
  conversational style (#391); specialist-to-specialist collaboration via the
  `consult_specialist` tool (#394)
- Humanlike follow-ups — progress-reports toggle, relationship familiarity, and
  task ETA (#392); bounded research-hard traits: humor timing, per-user growth,
  and group interjection (#393)
- Graph-augmented memory recall over the temporal knowledge graph (#395); broader
  memory & skill optimizations inspired by hermes-agent (#329)
- Concurrent mode — per-chat turn serialization with parallel tool execution
  (#320) and a chat-abort method to interrupt in-flight turns (#318)
- Mid-turn message injection for interactive agent turns (#330), with a
  real-time injection acknowledgement on non-web channels (#345)
- ACP-backed external subagent runtime (#283)

#### Tools

- `session_search` tool backed by a new SQLite FTS5 index over messages, for cross-conversation recall (schema migration v21, ported from hermes-agent's `session_search_tool.py`). Scoped to the caller's chat by default; cross-chat access goes through `authorize_chat_access` and the new `all_chats: true` opt-in is gated to control chats.
- `osv_check` tool that queries the OSV.dev advisory database for package vulnerabilities across npm, PyPI, crates.io, RubyGems, Maven, NuGet, Packagist, Hex, Pub, and Go (ported from hermes-agent's `osv_check.py`)
- `clarify` tool that sends a structured multi-choice or open-ended question through the caller's channel and releases the turn so the next user message naturally supplies the answer (ported from hermes-agent's `clarify_tool.py`)
- SSRF pre-flight checks on `web_fetch` that block requests pointing at loopback, link-local, private, CGNAT, unique-local IPv6, and cloud-metadata addresses (new `block_private_ips` field on `web_fetch_url_validation`, on by default; ported from hermes-agent's `url_safety.py`)
- Six further hermes-agent ports: prompt caching, fuzzy edit, guardrails, checkpoints, `@`-references, and subdir hints (#342)
- Multimedia tool suite (OpenAI-compatible, disabled by default, opt-in per tool via `media.<tool>.enabled`):
  - `generate_image` — POST `/v1/images/generations`; saves PNG under `<data_dir>/media/images/` and delivers via channel attachment when supported
  - `describe_image` — POST `/v1/chat/completions` with an image content block; accepts file paths (inside working_dir), URLs, or `data:` URIs
  - `text_to_speech` — POST `/v1/audio/speech`; saves MP3/OGG/etc. under `<data_dir>/media/audio/` and delivers via channel attachment
  - `transcribe_audio` — POST `/v1/audio/transcriptions` (multipart); exposes Whisper-style STT as an agent tool
  - Shared `MediaClient` enforces SSRF guard on the configured base URL, redacts API keys from `Debug`, and resolves credentials from (in order) `media.api_key`, `MICROCLAW_OPENAI_API_KEY`, `OPENAI_API_KEY`, or the existing top-level `openai_api_key`

#### Skills

- `propagation-trace` built-in skill (#384)
- Improved skill scores for microclaw (#279)
- Automated skill review CI for `SKILL.md` pull requests (#311)

#### Channels

- Telegram reply-chain support (#383)
- Native WeChat/Weixin (openclaw-weixin) support (#289) with markdown rendering in outbound messages (#324)
- Feishu/Lark ACK reaction (已读标记), opt-in with simplified emoji selection (#290)
- Mission Control gateway/session bridge and web auth UI improvements (#273, #278)

#### Packaging & release

- Official container image release automation for GHCR, with optional Docker Hub mirroring when repository credentials are configured (#277)
- Windows installer and gateway service support (#269)
- Snap package for Ubuntu and other snap-enabled distros (#325)
- `--full` / `-Full` flag across installer and Homebrew tap for heavy integrations
- Governance documents for security reporting, contribution expectations, and operator support
- CI coverage and dependency-audit gates; release packaging coverage for macOS artifacts and checksum publication
- Stronger config self-check coverage for risky execution settings

### Changed

- Heavy integrations are now optional build features; MCP returned to the default build, with `full` reserved for Matrix only (#313)
- Reduced release artifact size via release-profile tuning (#310)
- Raised the default web inflight limit to 10
- CI now builds the website docs alongside the web UI
- Docker builds now compile embedded web assets inside the image build and default the runtime image to `microclaw start`
- Release process documentation now points to explicit support and release-policy artifacts

### Fixed

- UTF-8-safe string slicing in `memory_backend.rs` and `web.rs` (#381)
- `install.ps1` renames the `$pid` parameter to avoid a PowerShell read-only variable (#344)
- Nix builds derive web npm deps from the lockfile via `importNpmLock` (#333)
- Config updates preserve YAML comments (#332)
- rustls websocket provider panic (#316) and restored websocket session compatibility (#298, #300)
- Normalized malformed OpenAI tool arguments (#304)
- Reflector strips thinking/variant tags from message content before LLM processing (#303)
- Runtime config loading and invalid-model fallback (#301)
- Feishu attachments, MiniMax tool calls, and scheduler retries (#299); WeChat PDF downloads (#302)

## 0.1.12

- Current release baseline before the maturity-hardening PR
