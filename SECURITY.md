# Security Policy

## Supported Versions

MicroClaw currently supports security fixes for the latest release on `main` and the most recent prior tagged release.

| Version line | Status |
|---|---|
| `main` / next release | supported |
| latest tagged release | supported |
| older releases | best effort only |

If a vulnerability requires coordinated disclosure, maintainers may patch `main` first and then decide whether the latest tagged release also receives a backport.

## Reporting a Vulnerability

Do not open a public GitHub issue for suspected security vulnerabilities.

Report privately by email to `security@microclaw.ai` with:

- affected version or commit SHA
- impact summary
- reproduction steps or proof of concept
- any known mitigations

If email is unavailable, open a GitHub Security Advisory draft instead.

## Response Targets

- Initial acknowledgement: within 3 business days
- Triage decision: within 7 business days
- Status update cadence: at least every 7 business days while the issue is active

These are targets, not guarantees, but they define the expected maintainer operating standard.

## Disclosure Process

1. Maintainers reproduce and assess severity.
2. A fix is prepared privately when practical.
3. Supported versions are patched or an upgrade-only advisory is issued.
4. A public advisory is published after a fix or mitigation is available.

## Security Baseline

Security-sensitive areas for this repository include:

- tool execution and sandbox routing
- auth, API keys, and web session handling
- file/path guard enforcement
- scheduler replay and cross-chat authorization
- MCP transport and remote tool integration

Changes in these areas should include tests, rollback notes, and user-visible documentation updates.
