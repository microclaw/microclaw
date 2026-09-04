---
id: embedding-rust
title: Rust SDK overview
description: Choose the right MicroClaw SDK layer and embed the shared Agent Engine in a Rust application.
slug: /sdk
---

# Rust SDK overview

`microclaw-sdk` is the supported facade for embedding MicroClaw in another Rust
application. It exposes stable Agent, Run, event, control, Skill, and Worker
contracts while keeping Server, Web, channel adapters, and desktop UI code out
of your dependency graph.

:::info Current distribution
The supported public crates are available on crates.io at `0.6.1`:
`microclaw-core`, `microclaw-engine`, and `microclaw-sdk`.
:::

## Decide whether the SDK is the right entry point

| Choose | When you need | What owns the process |
|---|---|---|
| MicroClaw Server | Channels, Web/API access, schedules, and an always-on service | MicroClaw |
| MicroClaw Work | A native project workspace with approvals and checkpoints | MicroClaw Work |
| `microclaw-sdk` | Agent behavior inside your own Rust product or service | Your application |

All three paths converge on the same provider-neutral Agent Engine. The SDK is
not a second or simplified agent loop.

## Choose a feature set

| Feature | What it provides | Typical host |
|---|---|---|
| `minimal` | Public contracts plus a host-provided `RunExecutor` | A small adapter around an existing execution backend |
| `standard` (default) | Runtime, Agent and Run lifecycle, controls, and local Worker | An application that owns execution but wants MicroClaw orchestration semantics |
| `remote-worker` | Authenticated WebSocket Worker client and host | A process that submits or executes work over the network |
| `full` | Configured Agent Engine, providers, tools, memory, Skills, MCP, hooks, Subagents, and remote Worker support | A product embedding MicroClaw's complete execution stack |

For a first integration, use `full`. Choose `minimal` or `standard` only when
your application deliberately provides its own executor.

## Supported public surface

- `MicroClaw`, `AgentBuilder`, and `AgentHandle` configure reusable agents.
- `RunHandle` streams ordered `RuntimeEventEnvelope` values and resolves to one
  terminal `RunResult`.
- `RunController` supports cancellation, steering, and approval decisions.
- `SkillCatalog` reports discovered Skills and why unavailable Skills could not
  be activated.
- `LocalWorker` and `RemoteWorker` share the same `Worker` contract.
- `RuntimeErrorCode` and `SdkError` let hosts handle failures without matching
  Server implementation details.

## Integration path

1. Complete the [SDK quickstart](./sdk-quickstart).
2. Learn the [Agent, Run, event, and control model](./sdk-concepts).
3. Add governed capabilities with [Skills](./sdk-skills).
4. Move execution behind [local or remote Workers](./sdk-workers) only when
   process isolation, capacity, or deployment topology requires it.
5. Use the [feature and crate guide](./sdk-features) before reducing dependency
   size or depending on lower-level crates directly.

The repository also contains
[compiling examples](https://github.com/microclaw/microclaw/tree/main/crates/microclaw-sdk/examples)
and a standalone downstream-consumer fixture used by CI.
