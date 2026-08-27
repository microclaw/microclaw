---
id: architecture
title: Architecture - Core Principles
sidebar_position: 9
---

This section explains how MicroClaw supports two product surfaces without
forking its agent behavior: an always-on Server and a native desktop Work app.
Both stay maintainable as channels, tools, models, and UI features grow because
they share the same runtime boundaries.

## Design goals

- Platform-agnostic agent core: conversation + tool behavior is not coupled to Server channel handlers or GPUI views.
- Two products, one execution model: Server and Work consume the same provider-neutral messages, tools, policy, approvals, checkpoints, and runtime events.
- Safe-by-default execution: tool permissions, risk levels, and explicit approval for dangerous operations.
- Durable state: sessions, messages, tasks, and memory persisted in SQLite/filesystem.
- Native Rust distribution: Server remains a predictable standalone service, while Work is a separate native desktop application with no bundled Web frontend.
- Extensibility: MCP tools + local skills + built-in tools, with clear boundaries.

## High-level runtime flow

```text
MicroClaw Server                         MicroClaw Work
chat / Web / APIs / protocols            native GPUI desktop
gateway + durable delivery               workspace + conversation projection
                 \                       /
                  shared Agent Engine
                  provider-neutral LLM layer
                  tools + policy + approvals
                  memory + skills + MCP
                  runtime events + checkpoints
```

Server translates channel ingress and delivery at its adapters. Work sends
foreground task requests to `microclaw-work-runtime`, then projects shared
runtime events into UI-independent Work state before GPUI renders it. Model
calls and tool execution never run on the GPUI thread.

## Core modules

- `microclaw-core` (`crates/microclaw-core`): shared errors, LLM types, and text utilities.
- `microclaw-storage` (`crates/microclaw-storage`): DB schema/queries, structured memory lifecycle, usage reporting.
- `microclaw-tools` (`crates/microclaw-tools`): tool runtime primitives (auth/risk/schema/path), sandbox, shared tool helper engines.
- `microclaw-channels` (`crates/microclaw-channels`): channel abstraction boundary and routing contracts.
- `microclaw-app` (`crates/microclaw-app`): app-level support modules (logging, bundled skills, transcribe).
- `microclaw-work-app` (`crates/microclaw-work-app`): UI-independent Work commands, projections, session persistence, and settings state.
- `microclaw-work-runtime` (`crates/microclaw-work-runtime`): foreground Work lifecycle and the bridge from the shared Agent Engine event stream.
- `microclaw-work` (`apps/microclaw-work`): native GPUI views, input, macOS integration, and packaging; it contains no separate agent loop.
- `src/` runtime layer (`src/main.rs`, `src/runtime.rs`, `src/agent_engine.rs`, `src/web.rs`, `src/channels/*.rs`, `src/tools/*.rs`): orchestration and concrete adapter/tool implementations.

## Product boundaries

| Boundary | MicroClaw Server | MicroClaw Work | Shared core |
|---|---|---|---|
| Primary role | Always-on service and delivery hub | Local desktop workspace | Agent execution and policy |
| Interface | Chat adapters, Web UI, HTTP/SSE/WebSocket, A2A/ACP | Native GPUI conversation and settings | Provider-neutral messages and runtime events |
| Lifecycle | Long-running channels, schedules, background tasks | Foreground local runs and durable Work sessions | Recovery, cancellation, checkpoints, tool loop |
| Platform | macOS, Linux, Windows | Apple Silicon macOS 13+ supported; Linux/Windows portable previews | Portable Rust crates |

Work attachment handling follows the same boundary. GPUI receives native file
drops, while `microclaw-work-app` canonicalizes each path against the selected
Workspace, persists only the relative reference, and rejects escapes. The
runtime then adds those references to the provider-neutral task request so the
existing governed filesystem tools—not the view—read any content.

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
