---
id: developer-guide
title: Developer Guide
sidebar_position: 10
---

This guide summarizes the internal structure and extension points.

## Quick start

```sh
git clone <repo-url>
cd microclaw
cp microclaw.config.example.yaml microclaw.config.yaml
# Edit microclaw.config.yaml with your credentials
cargo run -- start
```

## Project structure

```
crates/
    microclaw-core/      # Shared error/types/text modules
    microclaw-storage/   # SQLite + memory + usage reporting
    microclaw-tools/     # Tool runtime primitives and shared helper engines
    microclaw-channels/  # Channel abstraction boundary
    microclaw-app/       # App support modules (logging/skills/transcribe)

src/
    main.rs             # CLI entrypoint
    runtime.rs          # Runtime bootstrap + adapter startup
    channels/telegram.rs# Telegram adapter
    channels/discord.rs # Discord adapter
    channels/slack.rs   # Slack adapter (Socket Mode)
    channels/feishu.rs  # Feishu/Lark adapter (WS or webhook)
    channels/irc.rs     # IRC adapter (plain/TLS)
    config.rs           # Loads microclaw.config.yaml
    llm.rs              # Provider adapters (Anthropic/OpenAI-compatible/Codex)
    scheduler.rs        # Background scheduler
    tools/              # Built-in tool implementations + registry assembly
```

## Key types

| Type | Location | Description |
|---|---|---|
| `AppState` | `runtime.rs` | Shared runtime state for all adapters |
| `Database` | `microclaw_storage::db` | SQLite wrapper with `Mutex<Connection>` |
| `ToolRegistry` | `tools/mod.rs` | `Vec<Box<dyn Tool>>` dispatch |
| `Tool` / `ToolResult` | `microclaw_tools::runtime` | Shared tool trait + result/auth primitives |
| `LlmProvider` | `llm.rs` | Provider abstraction for Anthropic and OpenAI-compatible APIs |

## LLM provider conventions

- Keep `src/llm.rs` model-agnostic: do not branch on specific model names.
- Encode provider-specific behavior as capability flags (for example reasoning-field bridging or optional request params), then branch on capabilities.
- Add provider/model presets in setup/config surfaces, but keep request/translation logic in `llm.rs` driven by capabilities.
- Add tests for capability combinations rather than individual model name strings.

## Adding a new tool

1. Create `src/tools/my_tool.rs`
2. Implement the `Tool` trait from `microclaw_tools::runtime`
3. Add `pub mod my_tool;` to `src/tools/mod.rs`
4. Register it in `ToolRegistry::new()`

If your tool needs shared state (Bot or Database), add a constructor and pass it in at registration time.

## Debugging

```sh
RUST_LOG=debug cargo run -- start
RUST_LOG=microclaw=debug cargo run -- start
```

## Build

```sh
cargo build                              # default (all channels except Matrix, MCP included)
cargo build --features full              # all integrations (adds Matrix)
cargo build --release                    # release mode
cargo build --release --features full    # release mode with all integrations
cargo run -- start
```


## Extension tutorial

For a step-by-step extension workflow, see: [Skills + MCP Tutorial](./skills-mcp-tutorial).
