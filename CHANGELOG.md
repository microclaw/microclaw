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
- `session_search` tool backed by a new SQLite FTS5 index over messages, for cross-conversation recall (schema migration v21, ported from hermes-agent's `session_search_tool.py`)
- `osv_check` tool that queries the OSV.dev advisory database for package vulnerabilities across npm, PyPI, crates.io, RubyGems, Maven, NuGet, Packagist, Hex, Pub, and Go (ported from hermes-agent's `osv_check.py`)
- `clarify` tool that sends a structured multi-choice or open-ended question through the caller's channel and releases the turn so the next user message naturally supplies the answer (ported from hermes-agent's `clarify_tool.py`)
- SSRF pre-flight checks on `web_fetch` that block requests pointing at loopback, link-local, private, CGNAT, unique-local IPv6, and cloud-metadata addresses (new `block_private_ips` field on `web_fetch_url_validation`, on by default; ported from hermes-agent's `url_safety.py`)

### Changed

- CI now builds the website docs alongside the web UI
- release process documentation now points to explicit support and release-policy artifacts
- Docker builds now compile embedded web assets inside the image build and default the runtime image to `microclaw start`

## 0.1.12

- Current release baseline before the maturity-hardening PR
