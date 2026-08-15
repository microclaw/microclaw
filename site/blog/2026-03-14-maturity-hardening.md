---
slug: /maturity-hardening
title: "Maturity Hardening: Security Audit and Self-Checks"
authors: [microclaw]
tags: [release, reliability, web, runtime]
description: "MicroClaw's maturity hardening update adds security audit gates, operator self-checks, clearer release policy, and stronger release verification."
image: /img/blog/maturity-hardening/hero.svg
---

The latest maturity hardening pass in MicroClaw is not a flashy new model integration or another channel adapter. It is the kind of release work that makes the next ten releases safer: dependency audit gates, operator-visible risk checks, explicit support policy, and stricter release verification.

For an agent runtime, that matters. If your bot can execute tools, store memory, expose Web APIs, and run background work, "it compiles" is not enough. You also need repeatable checks around security posture, release shape, and operator safety defaults.

{/* truncate */}

## What shipped

This maturity hardening update landed in three layers:

- CI now includes a dedicated `Security Audit` job
- Web config self-checks now surface more operational risk signals
- repository policy docs now define security, support, and release expectations explicitly

None of that changes the core product story. It changes how confidently the project can move.

## Security Audit is now a real gate

The biggest mechanical change is straightforward: MicroClaw now runs dependency auditing as part of required CI, not as an optional follow-up.

The main CI workflow now includes:

- `cargo audit`
- `cargo deny check advisories bans licenses`

That matters for two reasons.

First, it catches security and maintenance drift before merge. During this hardening work, the audit surfaced an unmaintained transitive crate in the terminal UI dependency path. Fixing that forced the dependency graph to match the stated security baseline instead of silently relying on luck.

Second, it moves security review closer to normal engineering flow. A failing advisory check is now a normal PR failure, not an after-the-fact cleanup task.

This also flows into releases. The release-asset workflow now waits for required CI jobs including:

- `Web And Docs Build`
- `Security Audit`
- `Rust (ubuntu-latest)`
- `Rust (macos-latest)`
- `Stability Smoke`

That gives release automation a better contract: if the preconditions are not green, release packaging does not pretend otherwise.

## Docs builds are part of the path now

Another practical change: the site docs build is now checked alongside the embedded Web UI build from the `site/` workspace.

That sounds small, but it closes a common repo gap. Projects often keep runtime code and docs in the same repo, then accidentally validate only one of them in CI. The result is predictable:

- source docs drift from website docs
- links rot quietly
- release notes mention pages that were never actually built

MicroClaw now treats the docs site as part of the release surface rather than a side artifact.

## Operator self-check is more useful now

The most user-facing part of this hardening work is `GET /api/config/self_check`.

MicroClaw already had a local Web surface for operators. What changed here is the quality of the warnings it returns. Instead of acting like a shallow config echo, the self-check now flags conditions that actually correlate with risky runtime posture.

Examples include:

- operator password not configured
- Web host not bound to loopback
- sandbox disabled, or sandbox runtime unavailable
- high-risk tool confirmation disabled
- OTLP enabled without the expected endpoint configuration
- non-strict or disabled web-fetch validation
- scheduler failure-rate and reflector-idle conditions

This is the right kind of product hardening: not a giant policy engine, just an honest summary of whether the current config is safe enough to run the way you think it is.

If you are operating MicroClaw through the Web interface or an internal dashboard, this endpoint is now a much better first-stop health signal.

## Governance is now written down, not implied

This update also adds a set of explicit repository-level operating documents:

- `CHANGELOG.md`
- `SECURITY.md`
- `SUPPORT.md`
- `docs/releases/release-policy.md`

That may look like project-maintainer paperwork, but it has a real engineering effect.

Without those documents, teams end up guessing:

- Which version lines are actually supported?
- How should a security issue be reported?
- What checks are required before a tagged release?
- What counts as rollback-ready?

With those documents in place, there is less room for "tribal knowledge" to quietly decide release quality.

For a runtime that spans chat channels, Web APIs, tool execution, scheduling, and memory, explicit support and disclosure policy is not overhead. It is part of the product.

## Release packaging is stricter too

The release workflow now does more than just "build something on one runner and upload it."

It now verifies CI status for the tag commit, builds release archives across the supported target set, and generates checksums for published assets.

The current target matrix includes:

- Linux x86_64
- macOS x86_64
- macOS arm64
- Windows x86_64

That improves two things at once:

- release confidence for maintainers
- install trust for operators who want explicit artifact checksums

Again, this is not a shiny feature. It is a sign that the project is treating delivery as part of the runtime, not something outside it.

## How to use the new checks in practice

If you contribute to MicroClaw or run it seriously, there are three practical habits worth adopting.

### 1. Run dependency checks locally before pushing security-sensitive changes

```bash
cargo audit
cargo deny check advisories bans licenses
```

That is especially relevant when touching:

- auth
- Web APIs
- tool execution
- sandbox/runtime selection
- release workflows

### 2. Review config risk through the operator API

If you already have an operator API key, you can query the self-check directly:

```bash
curl -sS http://127.0.0.1:10961/api/config/self_check \
  -H "Authorization: Bearer $MICROCLAW_OPERATOR_API_KEY"
```

That gives you a faster read on unsafe defaults than manually scanning a long config file.

### 3. Treat docs and release policy as part of the change

If a PR changes security expectations, support posture, or release gates, it should update:

- runtime code
- repository docs
- website docs

MicroClaw now has a clearer path for that, and the release checklist reflects it.

## Why this kind of work matters

Agent runtimes accumulate risk in boring places.

Not just in model prompts or tool calls, but in:

- stale transitive dependencies
- soft CI expectations
- missing rollback criteria
- undocumented support policy
- operators not realizing a runtime is exposed with risky defaults

The point of maturity hardening is not to eliminate all risk. The point is to make the risk visible, enforce a minimum bar automatically, and stop shipping avoidable surprises.

That is what this update does.

## Read next

- [Web Operator API](/docs/web-operator-api)
- [Security Policy](/docs/security-policy)
- [Support Policy](/docs/support-policy)
- [Release Policy](/docs/release-policy)
- [PR & Release Checklist](/docs/release-checklist)
