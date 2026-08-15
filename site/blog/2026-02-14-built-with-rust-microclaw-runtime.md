---
slug: /built-with-rust-microclaw-runtime
title: "Built with Rust: MicroClaw as a Multi-Channel Agent Runtime"
authors: [microclaw]
tags: [architecture, rust, agents, telegram]
---

MicroClaw is no longer just a channel bot. In its current form, it is a **Rust multi-channel agent runtime** with a shared agent engine, provider abstraction, durable session state, and layered memory.

It supports Telegram, Discord, Slack, Feishu/Lark, IRC, and Web through adapters, while keeping one core execution path for reasoning and tool use.

Source code: https://github.com/microclaw/microclaw
Quick Start: https://microclaw.org/docs/quickstart

![MicroClaw system architecture](/img/blog/microclaw-runtime/01-system-architecture.svg)

<!-- truncate -->

## What MicroClaw Is Today

At a high level, MicroClaw combines:

- A single channel-agnostic agent loop (`src/agent_engine.rs`)
- A provider-agnostic LLM layer (`src/llm.rs`) with native Anthropic plus OpenAI-compatible providers
- Multi-step tool execution with schema-driven tool definitions
- Session resume + context compaction for long-running conversations
- Two memory layers: file memory and structured SQLite memory
- Background scheduling plus memory reflection jobs
- Usage and memory observability APIs for operational visibility

This architecture keeps product behavior consistent across channels while allowing independent evolution of adapters and providers.

## Why Built with Rust

Rust is a strong fit for this runtime shape:

- Tokio handles concurrent chat traffic and background loops with low overhead
- Strict types and ownership help keep tool/state boundaries predictable
- Shared state (`Arc<...>`) across runtime, tools, scheduler, and channels remains explicit
- A single compiled binary keeps deployment and operations straightforward

![Rust value map](/img/blog/microclaw-runtime/02-rust-value-map.svg)

## Core Runtime Shape

The runtime wiring in `src/runtime.rs` initializes providers, tools, memory services, channels, and background workers into one `AppState`.

The execution split is clean:

- **Adapters** (`channels/telegram.rs`, `channels/discord.rs`, `web.rs`) handle ingress/egress
- **Engine** (`agent_engine.rs`) runs the shared reasoning/tool loop
- **Provider layer** (`llm.rs`) abstracts model APIs and stream handling
- **Persistence** (`db.rs`) stores messages, sessions, tasks, memories, and observability

![Platform adapters and shared core pipeline](/img/blog/microclaw-runtime/03-platform-core-pipeline.svg)

## The Agent Loop

`process_with_agent` is the central path:

1. Optional explicit-memory fast path (`remember ...` / `记住...`)
2. Restore prior session or reconstruct from history
3. Build system prompt from file memory, structured memory, and skills catalog
4. Compact old context if limits are exceeded
5. Call selected LLM provider with tool schemas
6. On `tool_use`, execute tool(s), append results, and continue
7. On `end_turn`, persist session and return response

This gives MicroClaw controlled, iterative tool use while preserving resumability.

![Agent loop sequence](/img/blog/microclaw-runtime/04-agentic-loop-sequence.svg)

## Tool System and Safety

The tool system (`src/tools/mod.rs`) provides a common `Tool` trait and `ToolRegistry` dispatch with auth context injection.

Key traits of the current system:

- JSON-schema tool definitions consumed by providers
- High-risk tool approval gate in sensitive contexts
- Built-in tool docs generated from code to prevent doc drift
- Sub-agent mode with a restricted registry (`new_sub_agent`)

![Main agent vs sub-agent boundary](/img/blog/microclaw-runtime/05-main-vs-sub-agent-boundary.svg)

## Memory Is Layered, Not Monolithic

MicroClaw now uses two complementary memory layers.

### 1) File memory

- Global: `runtime/groups/AGENTS.md`
- Per chat: `runtime/groups/{chat_id}/AGENTS.md`

### 2) Structured memory (`memories` table)

- Normalized records with category/confidence/source/last_seen
- Archive lifecycle and supersede edges (`memory_supersede_edges`)
- Explicit-memory fast path + reflector extraction from conversation history

This layered design keeps user-facing notes simple while enabling queryable memory operations in SQLite.

![Memory hierarchy and lifecycle](/img/blog/microclaw-runtime/06-context-lifecycle.svg)

![File + structured memory model](/img/blog/microclaw-runtime/07-memory-hierarchy.svg)

## Scheduler + Reflector Background Jobs

Background workers in `scheduler.rs` run on intervals:

- Execute due scheduled tasks
- Trigger memory reflector passes
- Persist run metadata for observability

So MicroClaw is not only reactive to incoming messages, but also proactive through timed execution and memory maintenance.

![Scheduler and reflector lifecycle](/img/blog/microclaw-runtime/08-scheduled-task-lifecycle.svg)

## Cross-Channel Behavior

Each channel keeps its own delivery rules, but all share the same engine.

- Telegram and Discord apply adapter-specific mention and output limits
- Web supports send/stream APIs and replay endpoints
- Session/history/reset/delete behavior is unified through shared persistence

![Telegram vs Discord handling](/img/blog/microclaw-runtime/09-telegram-vs-discord-handling.svg)

## Data Model and Observability

`db.rs` now covers more than core chat storage. In addition to `chats/messages/sessions/scheduled_tasks`, it includes:

- Structured memory tables (`memories`, `memory_supersede_edges`)
- Memory observability tables (`memory_reflector_runs`, `memory_injection_logs`)
- Schema versioning and migration tracking (`db_meta`, `schema_migrations`)

Operational surfaces include:

- `/api/usage`
- `/api/memory_observability`
- Web Usage panel trend cards

![Database and observability schema](/img/blog/microclaw-runtime/10-database-er.svg)

## Extending MicroClaw

For new tools and capabilities:

1. Implement a new tool under `src/tools/`
2. Register it via `ToolRegistry`
3. Keep schemas explicit and docs generated from source
4. Reuse `process_with_agent` rather than adding platform-specific loops

This keeps the runtime coherent as features scale.

![New tool flow](/img/blog/microclaw-runtime/11-new-tool-flow.svg)

## Final Take

MicroClaw is best understood as a **Rust agent runtime**:

- Multi-channel adapters
- Provider abstraction
- Unified agent loop
- Durable sessions
- Layered memory with quality + reflection
- Production observability

That combination makes it a practical foundation for long-running, tool-using AI assistants.

![Built with Rust runtime summary](/img/blog/microclaw-runtime/12-closing-overview.svg)
