---
id: architecture
title: Architecture - Core Principles
sidebar_position: 9
---

This section explains how MicroClaw supports two product surfaces and embedded
Rust applications without forking agent behavior. The always-on Server, native
desktop Work app, and third-party applications all enter the same Agent Engine
through stable SDK and Runtime boundaries.

## Design goals

- Platform-agnostic agent core: conversation + tool behavior is not coupled to Server channel handlers or GPUI views.
- Multiple consumers, one execution model: Server, Work, and embedded applications consume the same provider-neutral requests, tools, policy, checkpoints, and runtime events.
- Safe-by-default execution: tool permissions, risk levels, and explicit approval for dangerous operations.
- Durable state: sessions, messages, tasks, and memory persisted in SQLite/filesystem.
- Native Rust distribution: Server remains a predictable standalone service, while Work is a separate native desktop application with no bundled Web frontend.
- Embeddability: applications use a small Rust facade without importing Server, Web, channel, or desktop UI code.
- Extensibility: MCP tools + local Skills + built-in tools, with clear boundaries.

## High-level runtime flow

```text
Server / Work / third-party Rust applications
                     |
               microclaw-sdk
                     |
              microclaw-engine
       Agent Loop + providers + Skills
        tools + policy + memory + MCP
                     |
              microclaw-runtime
       RunHandle + controls + events
          LocalWorker + capacity
                     |
        microclaw-core + capability crates
```

Server translates channel ingress and delivery at its adapters. Work sends
foreground task requests through `microclaw-sdk` and `microclaw-work-runtime`,
then projects shared runtime events into UI-independent Work state before GPUI
renders it. Embedded applications create an `AgentProfile`, submit a
`RunRequest`, and consume the same ordered events and terminal `RunResult`.
Model calls and tool execution never run on the GPUI thread.

## Core modules

- `microclaw-core` (`crates/microclaw-core`): stable Agent, Run, Worker, error, LLM, and event contracts.
- `microclaw-runtime` (`crates/microclaw-runtime`): UI-independent run lifecycle, handles, controls, concurrency, event streams, and Local Worker placement.
- `microclaw-engine` (`crates/microclaw-engine`): the concrete provider-neutral Agent Loop, providers, prompt/compaction, recovery, Skills, hooks, memory, and built-in tool assembly.
- `microclaw-sdk` (`crates/microclaw-sdk`): supported embedding facade and `minimal`, `standard`, and `full` feature presets.
- `microclaw-storage` (`crates/microclaw-storage`): DB schema/queries, structured memory lifecycle, usage reporting.
- `microclaw-tools` (`crates/microclaw-tools`): tool runtime primitives (auth/risk/schema/path), sandbox, shared tool helper engines.
- `microclaw-channels` (`crates/microclaw-channels`): channel abstraction boundary and routing contracts.
- `microclaw-app` (`crates/microclaw-app`): app-level support modules (logging, bundled skills, transcribe).
- `microclaw-work-app` (`crates/microclaw-work-app`): UI-independent Work commands, projections, session persistence, and settings state.
- `microclaw-work-runtime` (`crates/microclaw-work-runtime`): foreground Work lifecycle and the bridge from the SDK/Agent Engine event stream.
- `microclaw-work` (`apps/microclaw-work`): native GPUI views, input, macOS integration, and packaging; it contains no separate agent loop.
- root `src/`: Server CLI, Web/API, scheduler, gateway, and concrete channel assembly; it re-exports Engine modules temporarily for source compatibility.

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
2. [Embed MicroClaw in Rust](./sdk)
3. [Skills Architecture](./architecture-skills)
4. [MCP Architecture](./architecture-mcp)
5. [Channels and Gateway](./architecture-channels)

## Execution policy layer

Tool runtime includes an explicit execution policy tag:
- `host-only`
- `sandbox-only`
- `dual`

Current baseline:
- `bash`: `dual`
- file mutation tools (`write_file`, `edit_file`): `host-only`

Policy is evaluated before execution and combined with risk/approval checks.
