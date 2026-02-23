# AGENTS.md

## Project overview

MicroClaw is a Rust multi-channel agent runtime for Telegram, Discord, and Web.
It shares one channel-agnostic agent loop (`src/agent_engine.rs`) and one provider-agnostic LLM layer (`src/llm.rs`), with channel adapters for ingress/egress.

Core capabilities:
- Tool-using chat agent loop (multi-step tool calls)
- Session resume and context compaction
- Scheduled tasks + background scheduler
- File memory (`AGENTS.md`) + structured SQLite memory
- Memory reflector, quality gate, and observability metrics
- Skills + MCP tool federation
- ClawHub skill registry integration (search/install/lockfile)

## Tech stack

- Language: Rust (edition 2021)
- CLI args: clap
- Async runtime: Tokio
- Telegram: teloxide
- Discord: serenity
- Web API/UI: axum + React (in `web/`)
- Database: SQLite (rusqlite)
- LLM runtime: provider abstraction with native Anthropic and OpenAI-compatible providers

## Source index (`src/` + `crates/`)

Main orchestration files in `src/`:
- `main.rs`: CLI entry (`start`, `setup`, etc.)
- `runtime.rs`: app wiring (`AppState`), provider/tool initialization, channel boot
- `agent_engine.rs`: shared agent loop (`process_with_agent`), explicit-memory fast path, compaction, tool loop
- `hooks.rs`: hooks discovery/runtime/CLI (`hooks list/info/enable/disable`)
- `llm.rs`: provider implementations + stream handling + format translation
- `otlp.rs`: OTLP metrics exporter (HTTP/protobuf)
- `web.rs`: Web API router, shared web state, stream APIs, config endpoints
- `web/auth.rs`: auth handlers (session login/logout, password, API key lifecycle)
- `web/config.rs`: config read/update + config self-check handlers
- `web/sessions.rs`: session/history/reset/delete/fork/tree handlers
- `web/metrics.rs`: metrics snapshot/history handlers
- `web/stream.rs`: streaming send/status/SSE handlers
- `scheduler.rs`: scheduled-task runner + memory reflector loop
- `skills.rs`: skill discovery/activation
- `mcp.rs`: MCP server/tool integration
- `gateway.rs`: event stream / request lifecycle infra
- `setup.rs`: interactive setup wizard and provider presets
- `doctor.rs`: environment diagnostics
- `channels/*.rs`: concrete channel adapters (Telegram/Discord/Slack/Feishu)
- `tools/*.rs`: built-in tool implementations and registry assembly

Modularized crates in `crates/`:
- `microclaw-core`: shared error/types/text (`error`, `llm_types`, `text`)
- `microclaw-storage`: SQLite DB, memory domain, usage report assembly
- `microclaw-tools`: tool runtime primitives, sandbox, path guards, web/todo helpers
- `microclaw-channels`: channel abstractions (`channel`, `channel_adapter`, delivery boundary)
- `microclaw-app`: app-level support modules (logging, builtin skills, transcribe)

## Tool system

`src/tools/mod.rs` assembles built-in tools, while shared runtime primitives live in `microclaw-tools::runtime`:
- `Tool` trait (`name`, `definition`, `execute`)
- `ToolRegistry` dispatch and auth context injection
- risk/approval gate for high-risk tools in sensitive contexts

Current built-in tools are generated from code to avoid drift:
- `docs/generated/tools.md`
- `website/docs/generated-tools.md`

Regenerate docs artifacts with:
```sh
node scripts/generate_docs_artifacts.mjs
```

## Skills Storage

- Default skills dir: `<data_dir>/skills` (default `data_dir` is `~/.microclaw`)
- Config override: `skills_dir` in `microclaw.config.yaml` (e.g. `~/.microclaw/skills`)
- Compatibility policy: existing configured `data_dir` / `skills_dir` / `working_dir` keep working; new defaults apply only when unset
- ClawHub lockfile: `~/.microclaw/clawhub.lock.json`

## Agent loop (high level)

`process_with_agent` flow:
1. Optional explicit-memory fast path (`remember ...`/`记住...`) writes structured memory directly
2. Load resumable session from `sessions`, or rebuild from chat history
3. Build system prompt from file memory + structured memory context + skills catalog
4. Compact old context if session exceeds limits
5. Call provider with tool schemas
6. If `tool_use`: execute tool(s), append results, loop
7. If `end_turn`: persist session and return text

## Memory architecture

Two layers:

1. File memory:
- Global: `runtime/groups/AGENTS.md`
- Chat: `runtime/groups/{chat_id}/AGENTS.md`

2. Structured memory (`memories` table):
- category, confidence, source, last_seen, archived lifecycle
- explicit remember fast path
- reflector extraction from conversation history
- dedup/supersede handling with `memory_supersede_edges`

Observability tables:
- `memory_reflector_runs`
- `memory_injection_logs`

Surfaces:
- `/api/usage` summary block
- `/api/memory_observability` time-window series API
- Web Usage Panel trends/cards

## Database

`microclaw-storage::db` includes:
- schema creation + schema-version migrations (`db_meta`, `schema_migrations`)
- chat/message/session/task persistence
- structured memory CRUD + archive/supersede
- auth/session/api-key persistence (scopes, expiry, rotation)
- audit log persistence (`audit_logs`)
- usage and memory observability queries
- metrics history persistence (`metrics_history`)

## Web/API

`web.rs` routes include:
- chat send/send_stream + SSE stream replay
- auth APIs (`/api/auth/*`) with session cookie + API key scopes
- sessions/history/reset/delete/fork/tree
- config read/update + self-check (`/api/config/self_check`)
- audit query (`/api/audit`)
- metrics APIs (`/api/metrics`, `/api/metrics/summary`, `/api/metrics/history`)
- usage text report (`/api/usage`)
- memory observability series (`/api/memory_observability`)

## Hooks

Hook assets and spec:
- runtime hook dirs: `hooks/<name>/HOOK.md`
- hook spec doc: `docs/hooks/HOOK.md`
- sample hooks: `hooks/block-bash/`, `hooks/redact-tool-output/`

Hook runtime supports:
- events: `BeforeLLMCall`, `BeforeToolCall`, `AfterToolCall`
- outcomes: `allow`, `block`, `modify` (structured fields only)

## ClawHub

- local doc: `docs/clawhub/overview.md`
- web doc: `website/docs/clawhub.md`

## Observability Docs

- metrics docs: `docs/observability/metrics.md`
- operations runbook: `docs/operations/runbook.md`
- PR/release checklist: `docs/releases/pr-release-checklist.md`
- upgrade guide: `docs/releases/upgrade-guide.md`
- regression/stability reports: `docs/reports/*.md`

OTLP exporter supports bounded queue + retry backoff tuning:
- `otlp_queue_capacity`
- `otlp_retry_max_attempts`
- `otlp_retry_base_ms`
- `otlp_retry_max_ms`

## Build and test

```sh
cargo build
cargo test
npm --prefix web run build
npm --prefix website run build
```

Docs drift guard (CI + local):
```sh
node scripts/generate_docs_artifacts.mjs --check
```

## Collaboration conventions

- For the separate `website` repository (`microclaw.github.io`), do not open a PR by default; commit/push directly unless explicitly requested otherwise.
