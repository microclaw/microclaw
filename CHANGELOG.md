# Changelog

All notable changes to this project should be recorded in this file.

The format is loosely based on Keep a Changelog. Dates use UTC.

## Unreleased

### Added

- governance documents for security reporting, contribution expectations, and operator support
- CI coverage and dependency-audit gates
- release packaging coverage for macOS artifacts and checksum publication
- stronger config self-check coverage for risky execution settings
- official container image release automation for GHCR, with optional Docker Hub mirroring when repository credentials are configured
- `session_search` tool backed by a new SQLite FTS5 index over messages, for cross-conversation recall (schema migration v21, ported from hermes-agent's `session_search_tool.py`). Scoped to the caller's chat by default; cross-chat access goes through `authorize_chat_access` and the new `all_chats: true` opt-in is gated to control chats.
- `osv_check` tool that queries the OSV.dev advisory database for package vulnerabilities across npm, PyPI, crates.io, RubyGems, Maven, NuGet, Packagist, Hex, Pub, and Go (ported from hermes-agent's `osv_check.py`)
- `clarify` tool that sends a structured multi-choice or open-ended question through the caller's channel and releases the turn so the next user message naturally supplies the answer (ported from hermes-agent's `clarify_tool.py`)
- SSRF pre-flight checks on `web_fetch` that block requests pointing at loopback, link-local, private, CGNAT, unique-local IPv6, and cloud-metadata addresses (new `block_private_ips` field on `web_fetch_url_validation`, on by default; ported from hermes-agent's `url_safety.py`)
- Multimedia tool suite (OpenAI-compatible, disabled by default, opt-in per tool via `media.<tool>.enabled`):
  - `generate_image` — POST `/v1/images/generations`; saves PNG under `<data_dir>/media/images/` and delivers via channel attachment when supported
  - `describe_image` — POST `/v1/chat/completions` with an image content block; accepts file paths (inside working_dir), URLs, or `data:` URIs
  - `text_to_speech` — POST `/v1/audio/speech`; saves MP3/OGG/etc. under `<data_dir>/media/audio/` and delivers via channel attachment
  - `transcribe_audio` — POST `/v1/audio/transcriptions` (multipart); exposes Whisper-style STT as an agent tool
  - Shared `MediaClient` enforces SSRF guard on the configured base URL, redacts API keys from `Debug`, and resolves credentials from (in order) `media.api_key`, `MICROCLAW_OPENAI_API_KEY`, `OPENAI_API_KEY`, or the existing top-level `openai_api_key`

### Changed

- CI now builds the website docs alongside the web UI
- release process documentation now points to explicit support and release-policy artifacts
- Docker builds now compile embedded web assets inside the image build and default the runtime image to `microclaw start`

## 0.1.12

- Current release baseline before the maturity-hardening PR
