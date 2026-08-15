---
slug: /microclaw-weekly-updates-2026-02-26
title: "MicroClaw Weekly Update: Feb 20 - Feb 26, 2026"
authors: [microclaw]
tags: [release, runtime, channels, web, reliability]
---

This weekly update summarizes what changed in MicroClaw during **February 20, 2026 to February 26, 2026**.

The pace was high: channel coverage expanded, runtime reliability was hardened, and setup/config workflows became much better for multi-account bot operations.

<!-- truncate -->

## Scope

This post is based on the repository commit history in the 7-day window ending on **February 26, 2026**.

At a high level, recent changes cluster into these tracks:

- multi-account and multi-bot usability
- channel reliability and dedup behavior
- slash-command safety and command UX
- plugin framework and extensibility
- web/auth/config hardening
- provider/runtime compatibility updates

## 1) Multi-Account UX Moved From "Supported" to "Operational"

Multi-account runtime support existed, but configuration surfaces were still uneven in day-to-day usage.

Recent work closed that gap:

- setup and config paths continued migration toward account-based channel structure (`channels.<name>.accounts`)
- per-bot model overrides were propagated across runtime and setup
- setup/web config support was improved for multi-bot account editing workflows

Practical result: operators can manage more than one token/bot per channel with less manual YAML editing and lower risk of accidental config regression.

## 2) Channel Runtime Reliability: Duplicate Suppression and Startup Guards

A major reliability theme this week was “only process each inbound message once.”

Highlights included:

- cross-channel inbound dedup tightening
- Telegram/Feishu duplicate handling fixes
- startup-time message guards to avoid replay noise
- Feishu webhook retry and control-path fixes

These changes reduce repeated replies, improve idempotency under retries, and make cold starts less noisy in production.

## 3) Slash Commands Became Safer and More Predictable

Slash command behavior was standardized and hardened:

- slash inputs are treated as commands (not normal chat history content)
- unknown command handling was documented and normalized
- mention-gating behavior in groups/channels was tightened by default
- permissive mode remains explicit via `allow_group_slash_without_mention`

Net effect: better command safety in group contexts and cleaner model context history.

## 4) Plugin System Accelerated

The plugin line saw significant depth improvements:

- initial plugin framework for commands/tools/policies
- dynamic plugin tool naming without restart
- admin command and validation coverage improvements
- expanded matrix tests for plugin permissions and behavior

This gives teams a more realistic path to extending MicroClaw without forking core runtime logic.

## 5) Channel Coverage Expanded

During this window, channel support and channel architecture continued to broaden:

- IRC support matured
- Matrix support advanced quickly (including encrypted DM and stability work in this period)
- additional channel integrations (Signal, DingTalk, QQ) landed in channel/runtime paths

Combined with multi-account direction, this strengthens the “single runtime, many ingress surfaces” strategy.

## 6) Web/Auth/Config and Operator Hardening

Operator-facing reliability/security also moved forward:

- auth scope normalization and API key scope validation hardening
- web auth/session handling fixes
- config self-check/security posture improvements
- docs and generated artifact checks kept aligned with CI drift guards

The direction is clear: reduce operational surprises and make the safe path the default.

## 7) Provider and LLM Compatibility Work

Provider integration work focused on compatibility and guardrails:

- OpenAI-compatible response handling fixes
- body override support by provider/model surfaced and documented
- setup validation edge cases for OpenAI-compatible base URLs fixed

This lowers breakage risk when providers evolve API behavior.

## Version Cadence

The project continued fast release cadence in this period, with version bumps up through the `0.0.11x` line, reflecting ongoing incremental hardening and feature delivery.

## What To Watch Next

Based on this week’s direction, likely near-term priorities:

1. Continue reducing channel-specific edge-case divergence
2. Strengthen multi-account UX in setup/web/docs and migration safety
3. Expand plugin maturity from framework to production patterns
4. Keep reliability instrumentation and docs in lockstep with runtime behavior

