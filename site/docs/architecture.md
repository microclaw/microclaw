---
id: architecture
title: Architecture - Core Principles
sidebar_position: 9
---

This section explains how MicroClaw is designed for long-running agent workflows while staying maintainable as channels/tools/models grow.

## Design goals

- Platform-agnostic agent core: conversation + tool loop should not be tightly coupled to Telegram/Discord/Slack/Feishu/IRC/Web handlers.
- Safe-by-default execution: tool permissions, risk levels, and explicit approval for dangerous operations.
- Durable state: sessions, messages, tasks, and memory persisted in SQLite/filesystem.
- Single-binary operations: no required Python runtime, predictable deployment model.
- Extensibility: MCP tools + local skills + built-in tools, with clear boundaries.

## High-level runtime flow

```text
Channel event -> Gateway adapter -> Agent engine -> LLM + Tools loop
                 |                                 |
                 v                                 v
           channel persistence               state + memory + sessions
```

## Core modules

- `microclaw-core` (`crates/microclaw-core`): shared errors, LLM types, and text utilities.
- `microclaw-storage` (`crates/microclaw-storage`): DB schema/queries, structured memory lifecycle, usage reporting.
- `microclaw-tools` (`crates/microclaw-tools`): tool runtime primitives (auth/risk/schema/path), sandbox, shared tool helper engines.
- `microclaw-channels` (`crates/microclaw-channels`): channel abstraction boundary and routing contracts.
- `microclaw-app` (`crates/microclaw-app`): app-level support modules (logging, bundled skills, transcribe).
- `src/` runtime layer (`src/main.rs`, `src/runtime.rs`, `src/agent_engine.rs`, `src/web.rs`, `src/channels/*.rs`, `src/tools/*.rs`): orchestration and concrete adapter/tool implementations.

## Recommended reading order

1. [Context Lifecycle](./architecture-context)
2. [Skills Architecture](./architecture-skills)
3. [MCP Architecture](./architecture-mcp)
4. [Channels and Gateway](./architecture-channels)

## Execution policy layer

Tool runtime includes an explicit execution policy tag:
- `host-only`
- `sandbox-only`
- `dual`

Current baseline:
- `bash`: `dual`
- file mutation tools (`write_file`, `edit_file`): `host-only`

Policy is evaluated before execution and combined with risk/approval checks.
