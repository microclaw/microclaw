---
slug: /building-microclaw
title: "Building MicroClaw: A Practical Agent Runtime for Telegram and Beyond"
authors: [microclaw]
tags: [architecture, rust, telegram, agents]
---

MicroClaw is a Rust-based AI assistant that treats chat as an execution surface, not only a text interface.

It can run shell and file tools, browse the web, schedule jobs, and persist memory/session state so multi-step work can continue across turns.

![MicroClaw runtime overview](/img/blog/refresh-2026-02/01-building-microclaw-overview.svg)

<!-- truncate -->

## 2026-02-14 Update Snapshot

This post was refreshed on **February 14, 2026** to match the current codebase and docs.

Current shape:

- Shared agent loop with iterative `tool_use` / `tool_result` execution
- Channel adapters for Telegram, Discord, and Web API surfaces
- Provider abstraction for Anthropic + OpenAI-compatible endpoints
- Durable session resume with context compaction
- Layered memory: file memory (`AGENTS.md`) + structured SQLite memory
- Scheduler + memory reflection background jobs
- Usage and memory-observability endpoints for operations

## Why This Runtime Exists

Most chat bots still behave like single-turn wrappers:

1. Receive text
2. Produce text
3. Lose execution context

MicroClaw is built for a different loop:

1. Interpret an incoming task
2. Decide when tools are needed
3. Execute tools and read outputs
4. Iterate until done
5. Persist state for continuation

That makes it suitable for long-running workflows instead of one-shot Q&A.

## Core Capabilities

- Chat-native tool execution (`bash`, file ops, search/fetch, scheduler, memory)
- Full session resume including prior tool interaction context
- Context compaction for long-running conversations
- Global and per-chat memory via `AGENTS.md`
- Structured memory records in SQLite for queryable recall
- One-shot and cron-style scheduled runs
- Sub-agent delegation with reduced tool permissions

## Runtime Architecture

MicroClaw keeps one shared execution core and separates channel concerns into adapters.

- **Adapters**: Telegram / Discord / Web handle input-output constraints
- **Engine**: shared reasoning and tool loop
- **Persistence**: messages, sessions, tasks, memories, observability
- **Background workers**: scheduler and memory reflector

This keeps behavior consistent while allowing channels/providers to evolve independently.

## Why Rust

Rust is used here for operational reliability, not novelty:

- Explicit concurrency with Tokio for long-lived processes
- Predictable shared state boundaries
- Strong typing for tool/message/state protocols
- Single-binary deployment for simpler operations

## Design Principles

- `execution-first`: useful assistants should complete tasks, not only chat
- `state-is-a-feature`: session and memory quality are first-class
- `small-core-practical-edges`: keep core loop clear, add high-frequency features
- `layered-safety`: tool-level checks + chat access controls + deployment hardening
- `composable-growth`: evolve through tools and skills, avoid loop fragmentation

## Real Workflow Examples

- "Scan this repo for breaking changes and draft release notes."
- "Weekdays 9am: send me an AI news briefing from selected sources."
- "Read these logs, identify likely root causes, and propose fixes."
- "Remember my response style preference and apply it in future sessions."

## Current Priorities

1. Stronger default boundaries for high-risk tools
2. Better cross-channel behavior consistency
3. Clearer skill/tool boundary to reduce misuse
4. Better failure observability for sessions/scheduler/tools

## References

- MicroClaw repository: https://github.com/microclaw/microclaw
- Overview docs: https://microclaw.org/docs/overview
- Architecture docs: https://microclaw.org/docs/architecture
- Tools docs: https://microclaw.org/docs/tools
