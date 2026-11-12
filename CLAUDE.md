# MicroClaw

MicroClaw is a Rust multi-platform chat bot with a channel-agnostic core and platform adapters. It currently supports Telegram, Discord, Slack, Feishu/Lark, and Web, and can be extended to more platforms. It provides agentic tool execution, web search, scheduled tasks, and persistent memory. Inspired by [nanoclaw](https://github.com/gavrielc/nanoclaw/) (TypeScript/WhatsApp), incorporating some of its design ideas.

## Tech stack

Rust 2021, Tokio, teloxide 0.17, serenity 0.12, provider-agnostic LLM runtime (Anthropic + OpenAI-compatible), SQLite (rusqlite bundled), cron crate for scheduling.

## Directory overview

- `src/` -- Rust source for the bot binary
- `web/` -- Built-in Web UI (React + Vite). Compiled to `web/dist/` and embedded into the Rust binary via `include_dir!`. This is the chat interface and settings panel served by microclaw itself at runtime.
- `site/` -- Landing page and documentation site. It is versioned with this repository but is not part of the microclaw binary. Changes here have no effect on the bot runtime.

## Project layout

Products (all share one Agent Engine): **MicroClaw** (Server, this root crate), **MicroClaw Code** (`mccode`, `apps/microclaw-code`) and **MicroClaw SDK** (`crates/microclaw-sdk`).

- `crates/microclaw-core/` -- stable contracts: run protocol, runtime events, errors, LLM types, text/diff/redaction helpers
- `crates/microclaw-engine/` -- the Agent Engine: `agent_engine.rs` (agent loop), `tool_executor.rs`, `config/`, `llm/` (anthropic, openai, oai_translate, key_pool, sse, stream, resilience), `tools/` (built-in tools; registry in `tools/mod.rs`), `internal/storage/db/` (SQLite schema + query modules), `internal/tool_runtime/` (risk, auth, sandbox, path guard), `headless.rs`, `skills.rs`, `mcp.rs`, `hooks.rs`, `memory*.rs`
- `crates/microclaw-sdk/` -- supported embedding facade (`minimal` / `standard` / `full` presets)
- `crates/microclaw-code-core/` -- MicroClaw Code's UI-independent core: `home` (Code home + config), `project`, `trust`, `verify`, `git`, `sessions`, `driver` (one turn: run, approvals, verification, fix rounds), `launch` (engine, tool gate, role models and shell sandbox for a project — shared by every front end), `env` (engine env isolation, login-shell env), `session_lock` (one front end drives a session; `--take-over`), `setup` (first-run model setup)
- `apps/microclaw-code/` -- the `mccode` binary: full-screen TUI (`tui/`), `-p` / JSON printer (`print.rs`), `setup.rs`
- `apps/microclaw-code-desktop/` -- MicroClaw Code desktop app (macOS, GPUI via `gpui-kit`): its own workspace, `Cargo.lock` and `rust-toolchain.toml` (not built by the root workspace); `state.rs` (pure reducer), `service.rs` (Tokio service over `launch::project_engine` + `CodeSession::turn`), `views/`, `--smoke`; reaches the engine only through `microclaw-sdk` / `microclaw-code-core`; `scripts/bundle.sh` builds an unsigned `.app`
- `src/main.rs` -- Server CLI entry point (`microclaw code …` forwards to `mccode`)
- `src/runtime.rs` -- Server wiring (`AppState`), provider/tool initialization, channel boot
- `src/setup/` -- interactive Server setup wizard
- `src/web/` -- web API routes and streaming (state, server, dto, api_* route groups, pairing)
- `src/channels/*.rs` -- channel adapters (Telegram, Discord, Slack, Feishu, Weixin, …)
- `src/scheduler.rs` -- background scheduler + memory reflector loops; `src/outbox.rs` -- delivery outbox; `src/acp.rs` -- ACP server

## Key patterns

- **Agentic loop**: single entry `agent_engine.rs:run_agent_turn(state, AgentTurn)` (the `process_with_agent*` functions are shorthands): call provider -> if tool_use -> execute -> loop (up to `max_tool_iterations`)
- **Session resume**: full `Vec<Message>` (including tool_use/tool_result blocks) persisted in `sessions` table; on next invocation, loaded and appended with new user messages. `/reset` clears session.
- **Context compaction**: when session messages exceed `max_session_messages`, older messages are summarized and replaced with a compact summary + recent messages kept verbatim
- **Sub-agent**: `sub_agent` tool spawns a fresh agentic loop with 9 restricted tools (no send_message, write_memory, schedule, or recursive sub_agent)
- **Tool trait**: `name()`, `definition()` (JSON Schema), `execute(serde_json::Value) -> ToolResult`
- **Shared state**: `AppState` in `Arc`, tools hold `Bot` / `Arc<Database>` as needed
- **Group catch-up**: `db.get_messages_since_last_bot_response()` loads all messages since bot's last reply
- **Scheduler**: `tokio::spawn` loop, polls DB for due tasks, calls `process_with_agent` with `override_prompt`
- **Typing**: spawned task sends typing action every 4s, aborted when response is ready
- **Approval policy**: `approval_channels` (default web, code; control chats always) decides which callers need a human for high-risk tools (`ApprovalPolicy` in `tool_runtime/runtime.rs`, enforced in `ToolRegistry::execute_with_auth`); `read_only_subagent_channels` (default code) limits sub-agents to read-only tools; in-run approvals (`approval_broker`) accept approve/always/deny/defer
- **Local OS sandbox**: `sandbox.backend: local` (`internal/tool_runtime/local_sandbox.rs`) wraps shell commands with bubblewrap (Linux) or Seatbelt (macOS): read-only root, writable workspace/temp/tool caches/`writable_roots`, credential dirs hidden, `--unshare-net` / network deny when `no_network`; Landlock fallback (`tool_runtime/landlock.rs`, applied in `pre_exec`) when bwrap is unavailable; `SandboxRouter::local()` also wraps `run_in_background`
- **Path guard**: sensitive paths (.ssh, .aws, .env, credentials, etc.) are blocked in file tools via `path_guard` module
- **Platform-extensible core**: Telegram/Discord/Slack/Feishu/Web adapters reuse `process_with_agent`; new platforms integrate through the same core loop
- **SOUL.md**: optional personality file injected into system prompt. Loaded from `soul_path` config, `data_dir/SOUL.md`, or `./SOUL.md`. Per-chat overrides via `data_dir/runtime/groups/{chat_id}/SOUL.md`
- **Event tap + progress heartbeat**: non-web channels consume `AgentEvent`s concurrently with the agent loop via `EventTap` (`src/channels/event_tap.rs`); Telegram/Discord/Slack can opt into a throttled edit-in-place heartbeat (`channels.<name>.progress_updates`) with a percent bar (explicit `report_progress` calls win over an iteration/elapsed estimator), a live sub-agent count, and optional message pinning (`pin`, Telegram)
- **File-edit diffs**: `edit_file`/`write_file` attach a unified diff (`microclaw-core::diff`, `+N -M` stats, `diff_max_lines` cap) to `ToolResult::metadata`; `tool_executor` forwards it as `AgentEvent::FileDiff` → web SSE + ```diff chat messages behind the progress opt-in (`file_diffs_in_chat`)
- **Interactive approval buttons**: the `ApprovalRequired` option card renders as buttons on Telegram (inline keyboard + callback), Discord (components + interaction), Slack (Block Kit + Socket Mode `interactive` envelopes) and web; a tap stores a synthetic "1"/"2"/"3" reply and re-enters the text approval-parsing path
- **Reply-quote forwarding**: replying to an earlier message prepends `[quoted from <author>: …]` (shared `quoted_context_prefix` helper) on Telegram/Discord/Weixin
- **Context management**: `context_window.rs` (pure: per-model windows, token estimates, tool-output pruning, token split, structured summary prompt, fallback digest) driven by `agent_engine::compact_conversation`: pre-turn (tokens vs `ContextBudget`, or `max_session_messages` when > 0), mid-turn pressure (last observed input tokens, at most 2 per turn) and overflow-retry compaction; prune old tool results first, then incremental structured summary that re-injects the user's words and changed files; summarizer failure → mechanical digest; emits `RuntimeEvent::ContextCompacted`; `HeadlessRuntime::context_usage` / SDK `context_usage` back `/context`; the SDK `workspace` builder switches to token-based compaction, larger tool-result inlining, `explore_tool` and `context_budget_hint`; `context_note`/`rewind_context` (opt-in `context_tools`) are handled inside the loop, not the registry; `tools/explore.rs` is a synchronous read-only helper (ReadOnly class, runs in parallel) with project agents from `project_agents_dir`; `HeadlessRuntime::handoff_session` seeds a new session from a focused summary
- **Plan mode**: `/plan` (or ACP session mode "plan") restricts the loop to read-only tools and presents a plan; an approving reply executes it with the full toolset
- **Self-recheck**: opt-in (`self_recheck.enabled`) one-pass post-edit review before finalizing; hooks gained an observational `AfterTurn` event
- **Headless CLI**: `microclaw run -p "<prompt>" [--session <name>] [--json]` runs one prompt without channels (`src/headless.rs`)
- **API key rotation**: `api_keys` (top-level or per provider profile) forms a round-robin pool rotated on 401/403/429 (`KeyPool` in `src/llm/key_pool.rs`)
- **Per-chat model override**: `/model here <name>` / `/provider here <alias>` scope overrides to one chat (runtime-only, key `channel#chat_id`)
- **Interrupted-turn recovery**: interactive turns are tracked in the `active_turns` table (with a rolling `progress_text` checkpoint per tool iteration); on restart `src/turn_recovery.rs` notifies chats whose turn was killed mid-run — including how far it got — and retires orphaned sub-agent runs as `interrupted`
- **Server device pairing**: `src/web/pairing.rs` mints single-use codes (in-memory `PairingHub`) and trades them for hashed device tokens in `paired_devices` (schema v44, `db/pairing.rs`); `middleware.rs` resolves them to `device:<id>` actors with read+write scopes; `POST /api/runs/:run_id/cancel` is the HTTP twin of WS `chat.abort`. Used by `mccode remote pair` / `mccode -p --remote`
- **MicroClaw Code**: `mccode` reaches the engine only through `microclaw-sdk` (CI forbids a direct `microclaw-engine` dependency); caller channel `code`; `plan` mode uses `ToolPolicy::ReadOnly`, other modes `ToolPolicy::WorkspaceWrite` (`is_workspace_tool`); the TUI answers approvals in-run (run metadata `interactive_approvals` → `approval_broker` waits for `RuntimeControl::ResolveApproval`), while `-p` and chat channels keep the text path (run ends, next message `1`/`2`/`3`); per-project command allow rules (`microclaw-code-core::allow`, `~/.mccode/allow-rules.json`) cover single simple commands only; verification runs `.microclaw/project.yaml` / detected `auto` checks when the git worktree fingerprint changed and feeds failures back; `.microclaw/project.yaml` is honoured only for trusted projects (trust bound to the file's SHA-256, stored in `~/.mccode/trusted-projects.json`); trusted projects also load `AGENTS.md`/`CLAUDE.md`/`AGENT.md` into the prompt; `/undo`/`/rewind` use per-turn engine checkpoints (SDK `checkpoint`/`restore_checkpoint`), `/review` runs a `ToolPolicy::ReadOnly` turn over `git diff HEAD`, `/model` `/cost` `/compact` `/fork` map to SDK session APIs; shell commands run under the local OS sandbox by default (`--sandbox off`, `--no-network`; SDK `ShellSandbox`), and with network off ask mode auto-approves sandboxed commands; `mccode acp` (`apps/microclaw-code/src/acp/`: own JSON-RPC transport over `agent-client-protocol-schema` v1 types, config options for mode/model, slash commands, diffs, usage, terminal auth), `mccode mcp-server` (`mcp_server.rs`), `mccode -p --remote` (`microclaw-code-core::remote`, Server pairing + `/api/send_stream` SSE), `mccode eval` (`eval.rs`), `mccode update` (`update.rs`); Code also has `lsp.rs` (language-server diagnostics after edits, reported as an `lsp` check), `commands.rs` (custom slash commands), project memory `.microclaw/memory.md` (prompt), project `hooks` (`after_edit`/`after_turn`), `/handoff`, images via `@file` (`images.rs`, run metadata `image`), `--worktree` tasks and `review --pr` (`worktree.rs`), `/export`, `--max-session-tokens`; all Code state lives in `~/.mccode` (`MCCODE_HOME`). Code and Server are separate products with no compatibility shims: Code never reads a Server config (`--config`, `MCCODE_CONFIG`, `~/.mccode/config.yaml` or a settings profile only), its env vars are `MCCODE_*`, and `main.rs` `engine_env_overrides` replaces or clears the engine's Server `MICROCLAW_*` variables before the runtime starts
- **Code settings, rules and hooks**: `microclaw-code-core::settings` merges user (`~/.mccode/settings.yaml`), project (`.microclaw/settings.yaml`), local (`.microclaw/settings.local.yaml`) and managed layers (schema `docs/schema/code-settings.v1.json`, `mccode config …`); `rules.rs` (`allow`/`ask`/`deny` for bash/read/edit/net/mcp/agent/tool) and `user_hooks.rs` (Claude Code hook protocol) are enforced through the engine's embedder `ToolGate` (`crates/microclaw-engine/src/tool_gate.rs`, consulted in `ToolRegistry::execute_with_auth`, set via SDK `MicroClawBuilder::tool_gate`) by `gate::CodeToolGate`; the driver runs the non-tool hooks and per-role models (`model.roles`); `import.rs` imports Claude Code / Codex / OpenCode settings; `remote_notify.rs` + Server `src/remote_approvals.rs` / `src/web/code_remote.rs` push notifications and approval cards to chat channels
- **Code TUI**: `apps/microclaw-code/src/ui/` (theme tokens, Markdown, syntect/two-face highlighting, diff rendering) and `src/tui/` (`transcript.rs` per-item render cache, `view.rs` layout with side panel, `keys.rs` / `keymap.rs` configurable keys, `popup.rs`, `dialogs.rs`, `pager.rs` Ctrl+T, `review.rs` hunk review, `configure.rs` `/configure`, `notify.rs`, `preview.rs` render tests + `MCCODE_PREVIEW_DIR` HTML previews); fullscreen or inline (`tui.screen`)
- **Coding tool primitives**: `apply_patch` (`tools/apply_patch.rs`, Codex-style `*** Begin Patch` envelope, all-or-nothing, multi-file `file_diffs` metadata); `glob`/`grep` walk via `tools/workspace_walk.rs` (gitignore-aware); `tools/file_state.rs` `FileStateTable` (shared by a registry's read/write/edit tools) is the stale-read guard; `bash` `run_in_background` + `bash_output`/`bash_input`/`bash_kill` use the registry-owned `ProcessRegistry` (`tools/background_process.rs`), which kills its processes on drop
- **Delivery outbox**: final replies whose channel send fails are queued in `outbox_messages` and redelivered with backoff by `src/outbox.rs` (supervised loop); depth surfaces in the web Governance tab

## Build & run

```sh
cargo build
cargo run -- start    # requires config.yaml with at least one enabled channel plus model credentials
cargo run -- setup    # interactive setup wizard to create config.yaml
cargo run -- help
```

Web UI browser smoke test (Playwright, `web/e2e/`; needs `cargo build` first):
`npm --prefix web run e2e` — boots the built binary with a web-only config and
types/sends in the real embedded composer. See `docs/operations/web-ui.md`.

## Configuration

MicroClaw uses `microclaw.config.yaml` (or `.yml`) for configuration. Override the path with `MICROCLAW_CONFIG` env var. See `microclaw.config.example.yaml` for all available fields.

## Soul (personality customization)

MicroClaw supports a `SOUL.md` file that defines the bot's personality, voice, values, and working style. The file content is injected into the system prompt, replacing the default "helpful AI assistant" identity.

**Loading priority** (first match wins):
1. `soul_path` in config (explicit path)
2. `<data_dir>/SOUL.md`
3. `./SOUL.md` (project root, ships with the repo as the default soul)

**Per-chat override**: place a `SOUL.md` at `<data_dir>/runtime/groups/<chat_id>/SOUL.md` to give a specific chat a different personality.

**Presets**: `examples/soul/group-concise.md` ships a group-chat-tuned soul (short replies, match the asker's language, no markdown walls) for busy groups.

**Implementation**: `load_soul_content()` and `build_system_prompt()` in `src/agent_engine.rs`. The soul content is wrapped in `<soul>` XML tags in the system prompt.

## Adding a tool

1. Create `crates/microclaw-engine/src/tools/my_tool.rs` implementing the `Tool` trait
2. Add `pub mod my_tool;` to `crates/microclaw-engine/src/tools/mod.rs`
3. Register in `ToolRegistry::new()` with `Box::new(my_tool::MyTool::new(...))`

## Database

Core persistence is the engine's `Database` wrapper over SQLite. The query layer lives in `crates/microclaw-engine/src/internal/storage/db/` as domain modules (chats, sessions, tasks, subagents, memory, learning/{experience,skills,tracks}, auth, audit, outbox, turns, tool_cache, meta, usage) that each contribute an `impl Database` block behind the single facade; `schema.rs` holds the versioned migrations (frozen text — append new version blocks, never edit old ones).

## Important conventions

- All timestamps are ISO 8601 / RFC 3339 strings
- Cron expressions use 6-field format (sec min hour dom month dow)
- Messages are stored for all chats regardless of whether bot responds
- In groups, bot only responds to @mentions
- Consecutive same-role messages are merged before sending to the configured LLM provider
- Responses > 4096 chars are split at newline boundaries (Telegram), > 2000 chars for Discord, > 4000 chars for Slack/Feishu
