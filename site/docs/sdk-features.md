---
id: sdk-features
title: Features and crate boundaries
description: Select a MicroClaw SDK feature preset and understand the supported crate boundaries.
---

# Features and crate boundaries

Most applications should depend only on `microclaw-sdk`. Its feature presets
control how much implementation enters the dependency graph while preserving
the same public run protocol.

## Feature recipes

### Complete embedded Agent Engine

```toml
microclaw-sdk = { git = "https://github.com/microclaw/microclaw", features = ["full"] }
```

Use this for providers, tools, memory, Skills, MCP, hooks, Subagents, and Worker
transport in one host.

### Host-provided executor

```toml
microclaw-sdk = {
  git = "https://github.com/microclaw/microclaw",
  default-features = false,
  features = ["minimal"]
}
```

Implement `RunExecutor`, create a `Runtime`, and wrap it with
`MicroClaw::from_runtime`. This is appropriate when another system already owns
model and tool execution.

### Runtime plus remote Worker transport

```toml
microclaw-sdk = {
  git = "https://github.com/microclaw/microclaw",
  default-features = false,
  features = ["standard", "remote-worker"]
}
```

Use this for a control-plane application that submits work to another process.

## Published crate topology

The planned crates.io release contains reusable layers beneath the facade:

| Crate | Responsibility |
|---|---|
| `microclaw-core` | Stable run protocol, events, shared errors, and utilities |
| `microclaw-storage` | SQLite persistence and queries |
| `microclaw-tools` | Tool runtime primitives and safety boundaries |
| `microclaw-engine` | Configured Agent Engine implementation |
| `microclaw-runtime` | Agent, Run, control, and Worker lifecycle |
| `microclaw-worker` | Authenticated remote Worker transport and host |
| `microclaw-sdk` | Supported application-facing facade |

Direct lower-level dependencies are useful for framework integration, but they
couple the host more closely to MicroClaw internals. Prefer SDK re-exports until
you have a concrete capability that the facade does not expose.

## Compatibility expectations

- The workspace declares Rust 1.93 as its minimum supported Rust version.
- Serialized Worker messages are guarded by `WORKER_PROTOCOL_VERSION`.
- CI compiles standalone downstream consumers for `minimal`, `standard`, and
  `full`.
- The publication workflow checks public API compatibility against the previous
  crates.io release once a baseline exists.

Before upgrading, read the project [release policy](./release-policy) and
[upgrade guide](./upgrade-guide).
