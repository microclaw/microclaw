---
id: roadmap
title: Roadmap
sidebar_position: 15
---

This roadmap reflects current priorities. Items may shift as the project evolves.

## Already shipped

Everything in this section landed in v0.3.x–v0.4.0 and is documented elsewhere in
these docs. It is listed here because earlier versions of this page carried these
items as future work.

- **Tool permission model** — risk tiers, `tool_policy` allow/deny lists, per-chat
  standing grants, and structured approval option cards on web and chat channels
- **Tool execution sandboxing** — filesystem path guard, command runner limits, and
  egress policy
- **Observability** — metrics, traces, and structured logs with an OpenTelemetry and
  Langfuse path
- **Robust web fetch** — content validation, HTML extraction, and URL safety checks
- **Parallel tool execution within a turn** — bounded by `parallel_tool_max_concurrency`
- **Streaming responses** — server-sent events on the web surface
- **Group mention detection and reply quoting** — quoted-context forwarding on
  Telegram, Discord, and Weixin
- **Web UI console** — chat, settings, governance, usage, and task panels embedded in
  the binary
- **Multimodal input and output** — image description and generation, audio
  transcription, PDF rendering
- **Skill marketplace** — ClawHub with lockfile pinning and load-time integrity
  verification
- **Multi-agent orchestration** — `sub_agent`, `sessions_spawn`, specialist personas,
  fan-in summaries, and progress reporting

## Near term

- **Cut the next release.** A substantial body of work sits on `main` unreleased:
  plan mode, the headless one-shot CLI, API-key pool rotation, per-chat model and
  provider overrides, context-pressure compaction, approval buttons, and file-edit
  diff rendering.
- **Contributor build reliability.** Keep a clean clone building on current Node LTS
  releases rather than a single pinned major, and keep the local check script
  equivalent to CI.
- **Frontend supply chain.** Move the web UI off build tooling with open advisories
  and split the single-chunk bundle that ships inside the binary.

## Mid term

- **Sub-agent handoff contracts.** Harden parent/child result shaping for
  orchestration-heavy flows, with clearer timeout and cancel semantics.
- **Storage layer decomposition.** Split the monolithic query layer into
  domain-scoped modules so schema changes stay reviewable.
- **Dependency advisory burn-down.** Retire audit exceptions as upstream fixes land,
  keeping each remaining exception justified with removal criteria.

## Long term

- **Plugin host isolation.** Per-plugin principals and default-deny capabilities, per
  the plugin-host runtime decision recorded in the RFCs. This boundary ships when it
  is right, not to hit a date.
- **Deeper thread-bound routing.** Extend fan-out and fan-in patterns across channels
  with richer per-run observability.

## Non-goals

No enterprise SaaS build-out, no channel-count race, no vector database as a core
dependency, and no self-modifying tool code.
