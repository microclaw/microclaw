# MicroClaw

MicroClaw is a Rust multi-platform chat bot with a channel-agnostic core and platform adapters. It currently supports Telegram, Discord, Slack, Feishu/Lark, and Web, and can be extended to more platforms. It provides agentic tool execution, web search, scheduled tasks, and persistent memory. Inspired by [nanoclaw](https://github.com/gavrielc/nanoclaw/) (TypeScript/WhatsApp), incorporating some of its design ideas.

## Tech stack

Rust 2021, Tokio, teloxide 0.17, serenity 0.12, provider-agnostic LLM runtime (Anthropic + OpenAI-compatible), SQLite (rusqlite bundled), cron crate for scheduling.

## Directory overview

- `src/` -- Rust source for the bot binary
- `web/` -- Built-in Web UI (React + Vite). Compiled to `web/dist/` and embedded into the Rust binary via `include_dir!`. This is the chat interface and settings panel served by microclaw itself at runtime.
- `website/` -- **Separate git repository** (landing page + documentation site). Not part of the microclaw binary. Contains the public-facing marketing site and docs. Changes here have no effect on the bot.

## Project layout

- `crates/microclaw-core/` -- shared error/types/text modules (`error`, `llm_types`, `text`)
- `crates/microclaw-storage/` -- SQLite DB schema/query layer + memory/usage domain modules
- `crates/microclaw-tools/` -- tool runtime primitives (trait/auth/risk/schema/path) + sandbox
- `crates/microclaw-channels/` -- channel abstraction and delivery boundary modules
- `crates/microclaw-app/` -- app-level support modules (logging, builtin skills, transcribe)
- `src/main.rs` -- entry point, CLI
- `src/runtime.rs` -- app wiring (`AppState`), provider/tool initialization, channel boot
- `src/agent_engine.rs` -- shared agent loop (`process_with_agent`)
- `src/llm.rs` -- provider implementations + format translation
- `src/web.rs` -- web API routes and streaming
- `src/memory.rs` -- file-memory manager (`runtime/groups/.../AGENTS.md`)
- `src/scheduler.rs` -- background scheduler + memory reflector loops
- `src/channels/*.rs` -- Telegram/Discord/Slack/Feishu adapters
- `src/tools/*.rs` -- concrete built-in tools; registry assembly in `src/tools/mod.rs`

## Key patterns

- **Agentic loop** in `agent_engine.rs:process_with_agent`: call provider -> if tool_use -> execute -> loop (up to `max_tool_iterations`)
- **Session resume**: full `Vec<Message>` (including tool_use/tool_result blocks) persisted in `sessions` table; on next invocation, loaded and appended with new user messages. `/reset` clears session.
- **Context compaction**: when session messages exceed `max_session_messages`, older messages are summarized and replaced with a compact summary + recent messages kept verbatim
- **Sub-agent**: `sub_agent` tool spawns a fresh agentic loop with 9 restricted tools (no send_message, write_memory, schedule, or recursive sub_agent)
- **Tool trait**: `name()`, `definition()` (JSON Schema), `execute(serde_json::Value) -> ToolResult`
- **Shared state**: `AppState` in `Arc`, tools hold `Bot` / `Arc<Database>` as needed
- **Group catch-up**: `db.get_messages_since_last_bot_response()` loads all messages since bot's last reply
- **Scheduler**: `tokio::spawn` loop, polls DB for due tasks, calls `process_with_agent` with `override_prompt`
- **Typing**: spawned task sends typing action every 4s, aborted when response is ready
- **Path guard**: sensitive paths (.ssh, .aws, .env, credentials, etc.) are blocked in file tools via `path_guard` module
- **Platform-extensible core**: Telegram/Discord/Slack/Feishu/Web adapters reuse `process_with_agent`; new platforms integrate through the same core loop
- **SOUL.md**: optional personality file injected into system prompt. Loaded from `soul_path` config, `data_dir/SOUL.md`, or `./SOUL.md`. Per-chat overrides via `data_dir/runtime/groups/{chat_id}/SOUL.md`
- **Event tap + progress heartbeat**: non-web channels consume `AgentEvent`s concurrently with the agent loop via `EventTap` (`src/channels/event_tap.rs`); Telegram/Discord/Slack can opt into a throttled edit-in-place "⏳ Working…" heartbeat (`channels.<name>.progress_updates`)
- **Interrupted-turn recovery**: interactive turns are tracked in the `active_turns` table (with a rolling `progress_text` checkpoint per tool iteration); on restart `src/turn_recovery.rs` notifies chats whose turn was killed mid-run — including how far it got — and retires orphaned sub-agent runs as `interrupted`
- **Delivery outbox**: final replies whose channel send fails are queued in `outbox_messages` and redelivered with backoff by `src/outbox.rs` (supervised loop); depth surfaces in the web Governance tab

## Build & run

```sh
cargo build
cargo run -- start    # requires config.yaml with at least one enabled channel plus model credentials
cargo run -- setup    # interactive setup wizard to create config.yaml
cargo run -- help
```

## Configuration

MicroClaw uses `microclaw.config.yaml` (or `.yml`) for configuration. Override the path with `MICROCLAW_CONFIG` env var. See `microclaw.config.example.yaml` for all available fields.

## Soul (personality customization)

MicroClaw supports a `SOUL.md` file that defines the bot's personality, voice, values, and working style. The file content is injected into the system prompt, replacing the default "helpful AI assistant" identity.

**Loading priority** (first match wins):
1. `soul_path` in config (explicit path)
2. `<data_dir>/SOUL.md`
3. `./SOUL.md` (project root, ships with the repo as the default soul)

**Per-chat override**: place a `SOUL.md` at `<data_dir>/runtime/groups/<chat_id>/SOUL.md` to give a specific chat a different personality.

**Implementation**: `load_soul_content()` and `build_system_prompt()` in `src/agent_engine.rs`. The soul content is wrapped in `<soul>` XML tags in the system prompt.

## Adding a tool

1. Create `src/tools/my_tool.rs` implementing the `Tool` trait
2. Add `pub mod my_tool;` to `src/tools/mod.rs`
3. Register in `ToolRegistry::new()` with `Box::new(my_tool::MyTool::new(...))`

## Database

Core persistence is provided by `microclaw-storage` (`Database` wrapper over SQLite). Runtime state and observability tables are managed through versioned migrations.

## Important conventions

- All timestamps are ISO 8601 / RFC 3339 strings
- Cron expressions use 6-field format (sec min hour dom month dow)
- Messages are stored for all chats regardless of whether bot responds
- In groups, bot only responds to @mentions
- Consecutive same-role messages are merged before sending to the configured LLM provider
- Responses > 4096 chars are split at newline boundaries (Telegram), > 2000 chars for Discord, > 4000 chars for Slack/Feishu
