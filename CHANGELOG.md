# Changelog

All notable changes to this project should be recorded in this file.

The format is loosely based on Keep a Changelog. Dates use UTC.

## Unreleased

### Changed

- Clearer channel auth-failure logs — when a channel can't start because its credentials are
  rejected, Telegram/Discord/Slack/Feishu now log an actionable message ("authentication
  failed … check the token / run `microclaw setup`") instead of a generic or silent error,
  so a bad token isn't mistaken for the bot just going quiet. Part of the usability push.

### Added

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
