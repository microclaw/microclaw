# AGENTS.md

This file is the repository-level guide for coding agents working on MicroClaw. Keep it focused on architecture, change boundaries, and verification. User-facing setup and feature documentation belongs in `README.md`, `README_CN.md`, or `docs/`.

## Project at a glance

MicroClaw is a Rust agent runtime with one channel-independent agent loop and adapters for chat, web, and agent protocols. It supports multi-step tool use, resumable sessions, context compaction, scheduled work, file and SQLite memory, skills, plugins, MCP tools, ClawHub, subagents, hooks, and observability.

The main architectural boundaries are:

- `src/agent_engine.rs`: conversation and tool-use loop
- `src/llm.rs`: provider-independent LLM interface and provider translation
- `src/runtime.rs`: application assembly and channel startup
- `src/tools/`: built-in tool implementations and registration
- `src/channels/`: ingress and egress adapters
- `src/web.rs` and `src/web/`: HTTP, SSE, WebSocket, auth, and management APIs
- `crates/`: reusable core, storage, tools, channels, application, registry, and observability code

Do not duplicate the agent loop or provider logic in a channel adapter. Channel-specific code should translate messages and delivery events at the boundary, then call shared runtime behavior.

## Technology

- Rust 2021, Tokio, clap
- axum API and React UI in `web/`
- SQLite via rusqlite
- teloxide for Telegram and serenity for Discord
- native Anthropic and OpenAI-compatible LLM providers behind a shared abstraction
- MCP via `rmcp`; agent interoperability via A2A and ACP

The repository pins Rust in `rust-toolchain.toml`. Use that toolchain rather than silently changing it.

## Repository map

### Root application (`src/`)

- `main.rs`: CLI definitions and command dispatch
- `config.rs`, `config_persistence.rs`, `setup.rs`, `setup_def.rs`, `doctor.rs`: configuration, setup, and diagnostics
- `agent_engine.rs`: session recovery, prompt construction, compaction, LLM/tool loop, and persistence
- `llm.rs`, `prompt_cache.rs`, `completion_contract.rs`: model providers, caching, and completion guarantees
- `tool_executor.rs`, `tool_guardrails.rs`, `tools/`: tool execution, policy checks, and built-ins
- `skills.rs`, `skill_audit.rs`, `skill_review.rs`, `plugins.rs`: skill and plugin discovery, activation, and governance
- `mcp.rs`, `clawhub/`: external tool federation and ClawHub lifecycle
- `memory_backend.rs`, `memory_service.rs`, `embedding.rs`, `relationship.rs`, `mood.rs`: memory and personalization services
- `scheduler.rs`, `schedule_lifecycle.rs`, `supervision.rs`, `run_control.rs`, `turn_recovery.rs`, `checkpoint.rs`, `outbox.rs`: background work and reliability
- `gateway.rs`, `chat_turn_queue.rs`, `chat_commands.rs`: request lifecycle and chat control
- `a2a.rs`, `acp.rs`, `acp_subagent.rs`: agent-to-agent protocols and subagent execution
- `hooks.rs`: hook discovery, policy, runtime, and CLI
- `web.rs`, `web/`: web routes, auth, sessions, streaming, tasks, skills, governance, metrics, and WebSockets
- `channels/`: Telegram, Discord, Slack, Feishu, WeChat, DingTalk, QQ, WhatsApp, Signal, Matrix, IRC, Nostr, iMessage, and email adapters

### Workspace crates (`crates/`)

- `microclaw-core`: shared errors, LLM types, text utilities, redaction, and injection scanning
- `microclaw-storage`: SQLite schema/migrations, memory, quality, and usage queries
- `microclaw-tools`: tool runtime primitives, sandboxing, path/URL guards, caching, and web helpers
- `microclaw-channels`: channel traits, adapters, and delivery boundary
- `microclaw-app`: logging, bundled skills, and transcription support
- `microclaw-clawhub`: registry client, installation, gates, types, and lockfile support
- `microclaw-observability`: metrics, traces, logs, SDK, and external adapters

### Other important directories

- `web/`: React web client
- `skills/built-in/`: bundled skills; each skill has a `SKILL.md`
- `hooks/`: example/runtime hooks; each hook has a `HOOK.md`
- `docs/`: design notes, operations, security, RFCs, roadmaps, and generated references
- `tests/`: integration and black-box tests
- `scripts/`: documentation, release, packaging, and smoke-test helpers
- `packaging/`, `snap/`: distribution assets

## Where changes belong

- Put channel-neutral behavior in the shared agent/runtime layers, not in `src/channels/*`.
- Put reusable storage logic in `microclaw-storage`; keep SQL schema changes and migrations together.
- Put reusable tool execution and safety primitives in `microclaw-tools`; built-in product tools remain in `src/tools/`.
- Keep protocol transport details in `a2a`, `acp`, `mcp`, or channel modules and convert them to shared internal types at the boundary.
- When adding config, update the config type, defaults/setup path, example YAML, self-check behavior when relevant, and generated config documentation.
- When adding a tool, register it through `src/tools/mod.rs`, include its risk/auth behavior, add tests, and regenerate tool docs.
- When adding a web API, consider authentication scope, audit logging, streaming/replay semantics, and matching web-client types.
- When changing session or task lifecycle, check recovery, concurrency, cancellation, persistence, and all channel delivery paths.

## Agent loop invariants

The high-level `process_with_agent` flow is:

1. Handle explicit memory requests such as `remember ...` or `记住...` when the fast path applies.
2. Resume a stored session or rebuild context from chat history.
3. Build the system prompt from file memory, structured memory, active skills, and runtime context.
4. Compact context when configured limits are exceeded.
5. Call the selected provider with the common message and tool schema.
6. Execute tool calls through the registry, guardrails, hooks, and authorization context; append results and continue.
7. Persist the completed turn/session and deliver the final response.

Preserve provider-neutral message semantics and tool-call/result pairing. A provider-specific workaround must not leak into channel code or stored history unless the shared format explicitly requires it.

## Memory and persistence

File memory is stored under the configured data directory:

- global: `runtime/groups/AGENTS.md`
- per chat: `runtime/groups/{chat_id}/AGENTS.md`

Structured memory is stored in SQLite and includes lifecycle, confidence, source, deduplication, and supersession data. Relevant observability includes reflector runs and injection logs.

Database changes must:

- be backward-compatible through the schema migration mechanism;
- preserve existing configured `data_dir`, `skills_dir`, and `working_dir` behavior;
- include migration and query tests;
- avoid destructive rewrites of user data.

The default skills directory is `<data_dir>/skills`; `skills_dir` can override it. The ClawHub lockfile defaults to `~/.microclaw/clawhub.lock.json`.

## Hooks and tool safety

Hooks live at `hooks/<name>/HOOK.md`; the specification is `docs/hooks/HOOK.md`. Supported events include `BeforeLLMCall`, `BeforeToolCall`, and `AfterToolCall`, with `allow`, `block`, or structured `modify` outcomes.

Treat filesystem access, shell execution, network fetches, browser control, outbound messaging, and credential-bearing operations as security-sensitive. Use the existing sandbox, path guards, URL safety checks, approval/risk gates, redaction, and audit mechanisms instead of creating parallel checks.

## Generated documentation

The following references are generated from source and must not be hand-edited:

- `docs/generated/tools.md`
- `docs/generated/provider-matrix.md`
- `docs/generated/config-defaults.md`
- matching generated pages under `website/docs/` when that repository is present

Regenerate the files in this repository with:

```sh
node scripts/generate_docs_artifacts.mjs --no-website
```

Check this repository for drift with:

```sh
node scripts/generate_docs_artifacts.mjs --check --no-website
```

When the separate `website` repository is checked out at `website/`, omit `--no-website` to update or check both repositories. Without that checkout, omitting the flag creates an ignored partial `website/` tree. If `node` is not on `PATH`, report that limitation rather than editing generated files manually.

## Verification

Run the smallest relevant checks while iterating, then broaden according to the affected surface:

```sh
cargo fmt --all -- --check
cargo test
cargo clippy --workspace --all-targets --all-features -- -D warnings
npm --prefix web run build
node scripts/generate_docs_artifacts.mjs --check --no-website
```

Useful focused forms include `cargo test <test_name>`, `cargo test -p <crate>`, and `cargo check -p <crate>`. Matrix support is feature-gated; use `--all-features` or `--features channel-matrix` when changing it.

For documentation-only changes, at minimum verify local links, commands, file paths, generated-doc drift, and parity between `README.md` and `README_CN.md` where the content is shared.

## Documentation conventions

- `README.md` and `README_CN.md`: installation, quick start, configuration overview, and user-facing capabilities
- `DEVELOP.md` and `CONTRIBUTING.md`: contributor workflow and project policy
- `docs/operations/`: deployment and operational procedures
- `docs/security/`: threat model, execution model, and audits
- `docs/rfcs/`: durable architectural decisions
- `docs/roadmap/`: forward-looking plans; label status and date assumptions clearly
- `docs/reports/`: point-in-time findings; include the report date

Use repository-relative links in Markdown. Avoid copying large configuration or feature lists across several files; link to one canonical document instead. Mark historical plans as superseded or completed rather than letting them read as current instructions.

## Working conventions

- Preserve unrelated user changes in a dirty worktree.
- Prefer small, reviewable changes with tests near the affected module.
- Do not commit secrets, tokens, local database files, or generated runtime state.
- Keep English and Chinese README behaviorally aligned when changing shared user-facing facts.
- Update `CHANGELOG.md` for user-visible changes according to the release policy.
- For the separate `website` repository (`microclaw.github.io`), commit and push directly by default; open a pull request only when explicitly requested.
