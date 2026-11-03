---
id: architecture
title: Architecture - Core Principles
sidebar_position: 9
---

This section explains how MicroClaw supports three products without forking
agent behavior. The always-on Server, the MicroClaw Code terminal coding agent,
and third-party Rust applications all enter the same Agent Engine through
stable SDK and Runtime boundaries.

## Design goals

- Platform-agnostic agent core: conversation + tool behavior is not coupled to Server channel handlers or the Code terminal UI.
- Multiple consumers, one execution model: Server, Code, and embedded applications consume the same provider-neutral requests, tools, policy, checkpoints, and runtime events.
- Safe-by-default execution: tool permissions, risk levels, and explicit approval for dangerous operations.
- Durable state: sessions, messages, tasks, and memory persisted in SQLite/filesystem.
- Native Rust distribution: Server remains a predictable standalone service, while MicroClaw Code is a separate `mccode` binary without the Web frontend or channel adapters.
- Embeddability: applications use a small Rust facade without importing Server, Web, channel, or desktop UI code.
- Extensibility: MCP tools + local Skills + built-in tools, with clear boundaries.

## High-level runtime flow

```text
Server / Code / third-party Rust applications
                     |
               microclaw-sdk
                     |
              microclaw-engine
       Agent Loop + providers + Skills
       tools + policy + memory + MCP
       runtime + Worker + persistence
                     |
               microclaw-core
```

Server translates channel ingress and delivery at its adapters. MicroClaw Code
submits runs through `microclaw-sdk` only: `microclaw-code-core` drives a turn
(approvals, verification, fix rounds) and emits UI-independent updates that the
terminal UI renders. Embedded applications create an `AgentProfile`, submit a
`RunRequest`, and consume the same ordered events and terminal `RunResult`.

## Core modules

- `microclaw-core` (`crates/microclaw-core`): stable Agent, Run, Worker, error, LLM, and event contracts.
- `microclaw-engine` (`crates/microclaw-engine`): the concrete provider-neutral Agent Loop plus runtime, Worker, persistence, channels, observability, Skills, hooks, memory, and tool implementation.
- `microclaw-sdk` (`crates/microclaw-sdk`): supported embedding facade and `minimal`, `standard`, and `full` feature presets.
- Internal workspace crates remain as migration boundaries for the applications, but are not public crates.io packages.
- `microclaw-code-core` (`crates/microclaw-code-core`): MicroClaw Code's UI-independent core — project discovery, trust, verification, session index, and the turn driver. It depends on `microclaw-sdk`, never on the engine directly (enforced in CI).
- `microclaw-code` (`apps/microclaw-code`): the `mccode` binary — full-screen TUI and `-p` mode; it contains no separate agent loop.
- root `src/`: Server CLI, Web/API, scheduler, gateway, and concrete channel assembly; it re-exports Engine modules temporarily for source compatibility.

## Product boundaries

| Boundary | MicroClaw Server | MicroClaw Code | Shared core |
|---|---|---|---|
| Primary role | Always-on service and delivery hub | Coding agent in a local repository | Agent execution and policy |
| Interface | Chat adapters, Web UI, HTTP/SSE/WebSocket, A2A/ACP | Full-screen TUI and `-p` / JSON Lines | Provider-neutral messages and runtime events |
| Lifecycle | Long-running channels, schedules, background tasks | Foreground turns, approvals, verification and fix rounds | Recovery, cancellation, checkpoints, tool loop |
| Data | `~/.microclaw` | `~/.microclaw/code` (separate database and memory) | SQLite-backed storage |
| Platform | macOS, Linux, Windows | macOS, Linux, Windows (preview, from source) | Portable Rust crates |

A repository's `.microclaw/project.yaml` can change MicroClaw Code's mode,
instructions and check commands, so it is honoured only after the user trusts
that exact file content; trust decisions live in the Code home, never in the
repository. A repository-local `microclaw.config.yaml` is never loaded.

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
