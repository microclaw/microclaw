# Changelog

All notable changes to this project should be recorded in this file.

The format is loosely based on Keep a Changelog. Dates use UTC.

## Unreleased

### Added

- Per-task auxiliary models: a new `aux_models` config section lets a (typically
  cheaper) model handle ancillary work. Wired slots:
  - `aux_models.compaction` — context/history summarization.
  - `aux_models.reflector` — the background memory reflector (fact/triple extraction),
    which runs periodically per active chat.

  Each auxiliary model reuses the main provider profile and credentials — only the
  model name is swapped — and falls back to the main model when unset, so default
  behavior is unchanged. First steps toward the v0.3.0 "Self-Improving Runtime" plan
  (`docs/roadmap/v0.3.0-self-improving-runtime.md`).

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
