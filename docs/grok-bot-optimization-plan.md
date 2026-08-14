# MicroClaw Optimization Plan — Inspired by Grok Build & Grok Telegram Bot

**Date**: 2026-08-12
**References**: [xai-org/grok-build](https://github.com/xai-org/grok-build), [artickc/grok-telegram-bot](https://github.com/artickc/grok-telegram-bot), [xai-org/grok-prompts](https://github.com/xai-org/grok-prompts)

## Background

xAI open-sourced Grok Build (Rust agent harness + TUI) in mid-2026, and the community
project grok-telegram-bot (drives a Grok agent from Telegram over ACP) is the closest
analogue to MicroClaw's product shape. This document compares both against MicroClaw's
current codebase and plans the adoptions worth making. Each item was verified against
the code before being listed as a gap.

## Already Implemented (Verified)

- **MCP client**: `src/mcp.rs`, `src/tools/mcp.rs` — external MCP servers as tool sources.
- **ACP, both directions**: `src/acp.rs` serves ACP over stdio (`microclaw acp`), so
  external frontends can drive MicroClaw; `src/acp_subagent.rs` spawns external ACP
  agents as sub-agents.
- **Hooks**: `src/hooks.rs` (`BeforeLLMCall` / `BeforeToolCall` / `AfterToolCall`),
  discovered from `hooks/` dirs, CLI `microclaw hooks`.
- **Mid-turn message queueing + injection**: `src/chat_turn_queue.rs` queues messages
  arriving during an active turn and injects them into the running loop
  (`enable_mid_turn_injection`), emitting `AgentEvent::MidTurnInjection`.
- **Retry/backoff + model failover**: `src/llm.rs` — exponential backoff honoring
  `Retry-After`, `ResilientProvider` circuit breaker routing to `fallback_model`.
- **Crash recovery + delivery outbox**: `src/turn_recovery.rs`, `src/outbox.rs`,
  shadow-git checkpoints + `/rewind` (`src/checkpoint.rs`).
- **High-risk tool approval flow (text + web buttons)**: `AgentEvent::ApprovalRequired`
  carries a structured option card; web UI renders buttons, chat channels use a
  numbered-reply prompt (`src/messages.rs`, `src/agent_engine.rs`).
- **Voice transcription, per-channel multi-account, named provider profiles**
  (`/model`, `/provider` chat commands).

## Optimizations To Implement

### 1. [P0] Interactive Approval Buttons in Chat Channels

**Problem**: High-risk tool approval in chat is a numbered-text prompt ("reply 1/2/3").
The structured option card in `AgentEvent::ApprovalRequired` (`agent_engine.rs:107`) is
only rendered as buttons by the web UI (`web/src/main.tsx` `ApprovalBar`).

**Grok approach**: grok-telegram-bot pins an **Approve / Allow for session / Deny**
inline-keyboard message until selection or timeout.

**Implementation**:
- Telegram: render the option card as an inline keyboard; handle `callback_query`,
  map callback data to the existing `ApprovalReply::{ApproveOnce, ApproveAlways,
  DenyOrOther}` path, then edit the message to show the outcome.
- Discord: message components (buttons); Slack: Block Kit actions.
- Channels without interactive elements (IRC, email, Signal, …) keep the current
  numbered-text fallback — the parsing path stays as the universal fallback everywhere.
- Config: reuse `high_risk_tool_user_confirmation_required`; no new knobs needed
  beyond an optional per-channel `approval_buttons: true|false`.

**Files**: `src/channels/telegram.rs`, `src/channels/discord.rs`,
`src/channels/slack.rs`, `src/channels/event_tap.rs`, `src/agent_engine.rs` (no flow
change, only a channel-capabilities hint).

### 2. [P0] Unified Diff Rendering for File Edits

**Problem**: `edit_file` / `write_file` return a plain success sentence; users never see
what changed. `src/checkpoint.rs` explicitly notes per-checkpoint diff is not exposed.

**Grok approach**: every file change renders as a unified diff block with `+N -M`
stats, capped at a configurable line count (default 120).

**Implementation**:
- Add the `similar` crate. In `edit_file`/`write_file`, compute a unified diff between
  before/after content and attach it to the `ToolResult` as a display-only field.
- Event tap / channel delivery renders it as a ```diff fenced block with `+N -M`
  header, truncated at `tools.diff_max_lines` (default 120).
- Bonus: implement per-checkpoint diff for `/rewind` previews using the same helper.

**Files**: `src/tools/edit_file.rs`, `src/tools/write_file.rs`, `src/checkpoint.rs`,
`src/channels/event_tap.rs`, `crates/microclaw-core` (shared diff helper), `Cargo.toml`.

### 3. [P0] Reply-Quote Context Injection Across Channels

**Problem**: When a user replies to an earlier message, only Weixin injects the quoted
content (`src/channels/weixin.rs:1552`, and only the title). Telegram uses
`reply_to_message` solely to decide whether to respond; Discord/Matrix/Feishu don't
extract the referenced message at all. Terse follow-ups like "为什么？" lose their target.

**Grok approach**: replying forwards the referenced content (and exact highlighted
quotes) alongside the new prompt.

**Implementation**:
- Add a shared formatting helper (e.g. `quoted_context(author, excerpt)` →
  `[quoted from {author}: {excerpt}]\n{text}`) in `crates/microclaw-core/text` or
  `src/messages.rs`, with an excerpt cap (~500 chars).
- Telegram: extract `reply_to_message` text/caption. Discord: `referenced_message`.
  Slack: fetch thread parent when replying in-thread. Matrix: `in_reply_to` event.
  Upgrade Weixin to use full referenced content, not just the title.

**Files**: `src/channels/{telegram,discord,slack,matrix,weixin}.rs`, `src/messages.rs`.

### 4. [P1] Context-Pressure Auto-Compaction & Overflow Recovery

**Problem**: Compaction triggers only pre-turn and only on message **count**
(`messages.len() > max_session_messages`, `agent_engine.rs:1605`). Nothing fires
mid-turn under token pressure, and a provider "context length exceeded" error is not
handled — the turn just fails.

**Grok approach**: fork/compact automatically at ~85% context usage; on stream error
after partial output, ask the same session to continue from the partial reply.

**Implementation**:
- Track an estimated token total per loop iteration (usage from the previous provider
  response is already available); when it crosses
  `context_pressure_compact_pct` (default 85) of the model's window, run the existing
  `compact_messages()` mid-turn before the next provider call.
- Catch context-length-exceeded errors in `llm.rs` call paths (classify by provider
  error code/message), compact once, retry the call; fail with today's behavior if it
  still overflows.
- Keep the count-based trigger as-is.

**Files**: `src/agent_engine.rs`, `src/llm.rs`, `src/config.rs`.

### 5. [P1] Richer Progress Reporting (Percent + Activity Fallback)

**Problem**: The heartbeat shows only "⏳ Working — step N, using `tool`…"
(`src/channels/event_tap.rs:60`).

**Grok approach**: the agent may emit `{progress: N%}` markers which render as a
0–100% bar; without markers, a fallback estimator derives progress from real activity
(tool calls, streamed output, elapsed time) so weaker models still show motion.

**Implementation**:
- Recognize an optional `{progress: N}` marker in assistant text (strip before
  delivery), carry it on `AgentEvent`.
- Fallback estimator in `event_tap`: blend iteration count vs `max_tool_iterations`
  and elapsed time into a coarse percent; render a compact unicode bar
  (`▰▰▰▱▱ 60%`) in the heartbeat line and persist it to `active_turns.progress_text`
  so restart-recovery messages also show how far the turn got.

**Files**: `src/channels/event_tap.rs`, `src/agent_engine.rs`.

### 6. [P1] Sub-Agent Lifecycle Visibility

**Problem**: Completion notices and `report_progress` milestones exist, but there is no
spawn notice and no live "N running" indicator; `event_tap` has no subagent awareness
(no `AgentEvent` variants for subagent start/finish).

**Grok approach**: shows each subagent's start/work/finish plus a live "🤖 N running"
summary.

**Implementation**:
- Add `AgentEvent::SubagentStarted { run_id, label }` and `SubagentFinished { run_id,
  status }` emitted from `src/tools/subagents.rs` / `src/acp_subagent.rs`.
- `event_tap` appends "🤖 {n} running" to the heartbeat while any are active.

**Files**: `src/agent_engine.rs` (event enum), `src/tools/subagents.rs`,
`src/acp_subagent.rs`, `src/channels/event_tap.rs`.

### 7. [P2] Plan Mode

**Problem**: No propose-plan-then-approve flow. ACP advertises a single session mode
("chat", `src/acp.rs:401`).

**Grok approach**: Plan Mode is a headline grok-build feature — the agent plans with
read-only tools, the user reviews/approves, then execution proceeds.

**Implementation**:
- New session mode `plan` (ACP `set_session_mode` + chat command `/plan`): the tool
  registry is filtered to read-only tools; the turn ends by presenting the plan
  through the existing `ApprovalRequired` card (Approve → re-run with full tools and
  the plan pinned into context; Deny → stay in plan mode).
- Per-chat mode state in runtime meta, cleared by `/reset`.

**Files**: `src/acp.rs`, `src/chat_commands.rs`, `src/agent_engine.rs`,
`src/tool_executor.rs`.

### 8. [P2] Post-Turn Self-Recheck + `AfterTurn` Hook Event

**Problem**: No quality pass after file-modifying turns; hooks lack a post-turn event.
Evidence-based verification exists only for sub-agents (`src/completion_contract.rs`).

**Grok approach**: optional gated `SELF_RECHECK` — after file-modifying turns, one
review pass runs before "Done", with a templated prompt.

**Implementation**:
- Add `HookEvent::AfterTurn` to `src/hooks.rs` (fired with a turn summary payload).
- Config `self_recheck: { enabled, prompt_template }` (off by default, `{{USER}}` /
  `{{RESULT}}` placeholders): when a turn executed file-modifying tools, run one extra
  agent iteration with the template before finalizing; cap at one pass per turn.

**Files**: `src/hooks.rs`, `src/agent_engine.rs`, `src/config.rs`.

### 9. [P2] Headless One-Shot CLI

**Problem**: No way to run a single prompt without a channel or an ACP client —
`MainCommand` has no `run`/`-p` (`src/main.rs:62-108`). grok-build ships headless
mode for scripting/CI.

**Implementation**:
- `microclaw run -p "<prompt>" [--session <id>] [--json]`: wire directly to
  `process_with_agent`, print the final text (or a JSON envelope with usage/tool
  trace) to stdout, exit non-zero on failure. Reuse the web channel identity for
  storage so sessions are inspectable afterwards.

**Files**: `src/main.rs`, `src/runtime.rs`.

### 10. [P2] API-Key Pool Rotation

**Problem**: `api_key` is a single field per provider profile; the circuit breaker can
fail over to another **model** but not rotate credentials. grok-telegram-bot rotates
saved accounts on transient errors.

**Implementation**:
- Allow `api_keys: [..]` (list) alongside `api_key`; on retryable auth/429/5xx errors,
  advance to the next key before counting a circuit-breaker failure; surface rotation
  stats in `provider_failover_snapshot()`.

**Files**: `src/llm.rs`, `src/config.rs`.

### 11. [P3] Concise Group-Chat Soul Preset

The published `@grok` prompt encodes rules that map directly onto group-chat pain
points: short replies (<550 chars), no markdown walls, match the language of the
message being answered, don't moralize. Ship these as an optional soul preset
`examples/soul/group-concise.md` and reference it from the SOUL.md docs.

### 12. [P3] Per-Chat Model/Provider Override

`/model` and `/provider` currently override per **channel**
(`set_model_override_for_channel`). Extend the override maps to accept
`channel:chat_id` keys so a single busy group can run a cheaper/faster model without
affecting the whole channel.

**Files**: `src/chat_commands.rs`, `src/runtime.rs`, `src/config_persistence.rs`.

### 13. [P3] Pinned Auto-Clearing Status Panel (Telegram)

Optionally pin the progress-heartbeat message during long turns and unpin+finalize on
completion (`pin_chat_message`/`unpin_chat_message`), keeping long-running task status
visible in busy groups. Off by default.

**Files**: `src/channels/telegram.rs`, `src/channels/event_tap.rs`.

## Explicitly Not Adopting

- **Grok 4.20 four-agent cross-verification architecture**: too heavy for a chat bot;
  the existing specialists/sub-agent tools cover the need on demand.
- **Fullscreen TUI**: unrelated to MicroClaw's product shape (channels + web UI).

## Rollout

Each P0 item ships as an independent PR with unit tests (diff helper, quote formatter,
callback-data parsing) plus a manual channel smoke test; P0 targets the next minor
release. P1 items follow once P0 lands (progress percent builds on the event-tap
changes; context-pressure compaction needs soak time behind a config default-off
flag for one release before flipping on). P2/P3 are scheduled opportunistically;
Plan Mode (#7) should land after approval buttons (#1) since it reuses the approval
card UX.
