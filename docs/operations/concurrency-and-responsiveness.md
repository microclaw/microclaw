# Concurrency and Responsiveness

This note answers a recurring architecture question: does MicroClaw still behave like a single blocking agent loop, or can it already move toward a more Spacebot-like non-blocking design?

Short answer:

- the runtime as a whole is multi-lane: channel adapters, scheduler, reflector, web stream runs, and subagents all run on independent async lanes
- inside a single turn, ReadOnly tool calls execute in parallel by default; mid-turn user messages are injected into the active loop instead of waiting for `end_turn`
- session-native subagents remain the durable background lane for orchestration-heavy or long-running work

The rest of this note describes the building blocks, the limits that still matter, and the status of the umbrella concurrency roadmap from issue #307.

## What is concurrent today

MicroClaw is not one global blocking session.

- Channel runtimes are started independently from `src/runtime.rs`, so Telegram, Discord, Slack, Web, and other adapters do not all wait on one shared blocking loop.
- The web streaming path creates background run tasks and emits replayable SSE events from `src/web/stream.rs`.
- Scheduler jobs and reflector passes are spawned independently from `src/scheduler.rs`.
- Session-native subagents are accepted immediately, then continue in the background via the runtime in `src/tools/subagents.rs`.
- Per-chat turn serialization is universal: `ChatTurnQueue` in `src/chat_turn_queue.rs` ensures at most one agent run per `(channel, chat_id)`, and additional messages arriving during an active turn are queued rather than dropped or racing.
- Inside one turn, the tool executor in `src/tool_executor.rs` partitions tool calls into execution waves by `ToolConcurrencyClass` (`ReadOnly`, `SideEffect`, `Exclusive`) and runs the ReadOnly subset of each wave concurrently up to `parallel_tool_max_concurrency`.
- Mid-turn message injection in `src/agent_engine.rs` picks up new user messages between tool-loop iterations (and at `end_turn`) when `enable_mid_turn_injection` is on, so a follow-up does not have to wait for the previous turn to finish.

In practice, this means one long-running web request, scheduled task, or subagent run does not freeze the whole process, and a single turn can fan out safe tool work in parallel.

## What is still sequential

A single turn still drives the model call, tool result hand-off, and any compaction step in order through `src/agent_engine.rs`. So:

- model calls themselves are not pipelined inside one turn
- `SideEffect` and `Exclusive` tools (e.g. writes, `bash`, `activate_skill`) still serialize relative to each other and to the rest of the wave, by design
- compaction and persistence happen on the same task as the run

This is intentional. Parallelizing model calls or side-effecting tools inside one turn would change the semantic contract of a turn, not just its scheduling.

## Existing non-blocking building blocks

### Web streaming

The web surface is the clearest example of current responsiveness:

- `POST /api/send_stream` returns a `run_id` immediately
- `/api/stream` replays `status`, `tool_start`, `tool_result`, `delta`, `mid_turn_injection`, and terminal events
- clients can reconnect and resume from the last seen event id

This already gives MicroClaw a non-blocking UX on the web surface.

### Background scheduler and reflector

Two expensive classes of work are already split out of the interactive turn path:

- scheduled tasks
- structured-memory reflection

That avoids forcing every chat turn to pay the latency of those jobs inline.

### Session-native subagents

The current answer to "can it behave more like Spacebot" is largely "yes, through subagents, with scoped limits".

- `sessions_spawn` returns immediately with `status=accepted`
- the child run progresses through `accepted -> queued -> running -> completed|failed|timed_out|cancelled`
- completion can be announced back to the parent chat
- operators can inspect or control the run with `subagents_list`, `subagents_info`, `subagents_log`, `subagents_focus`, `subagents_send`, `subagents_orchestrate`, and `subagents_kill`

This is not the same as fully decomposing the whole product into many independent worker processes, but it already establishes a durable background execution lane.

### Per-chat turn queue

`ChatTurnQueue` is shared by every channel adapter (Telegram, Discord, Slack, Feishu, Matrix, Web). Messages that arrive while a turn is active are coalesced into the running turn (via mid-turn injection) or queued for the next turn, with a configurable upper bound. This replaced the ad-hoc per-channel locks that previously existed in only some adapters.

### Intra-turn tool waves

When the model emits multiple tool calls in one response, `tool_executor::partition_into_waves` groups them so that ReadOnly tools (e.g. `read_file`, `glob`, `web_search`) within a wave run concurrently while side-effecting and exclusive tools execute alone. This is the default behavior; tune `parallel_tool_max_concurrency` and `tool_concurrency_overrides` to adjust.

### Mid-turn message injection

When a user sends a follow-up while a turn is mid-flight, `enable_mid_turn_injection` (default `true`) folds the new content into the same agent loop between iterations. The model sees the follow-up in its very next iteration without waiting for the previous turn to terminate. The web stream surfaces this to clients as a `mid_turn_injection` event.

### Non-web channel injection acks

Telegram, Discord, Slack, Matrix, Feishu, and WeChat used to drain `AgentEvent`s only after the agent loop returned, which meant a user who sent a follow-up mid-turn saw nothing until the turn ended. The shared helper in `src/channels/event_tap.rs` now consumes events concurrently with the agent loop on every channel adapter, so a `MidTurnInjection` event triggers an immediate ack message on the channel where the follow-up was sent. Controlled by the `mid_turn_injection_echo` config flag (default `true`); has no effect when `enable_mid_turn_injection` is `false`. Feishu's existing in-place progress message picks up the ack as an extra line; the other channels post a small standalone ack.

## Limits that still matter

- Streaming visibility is strongest on the web surface. Chat channels now consume `MidTurnInjection` events concurrently with the agent loop and ack them in real time (see `src/channels/event_tap.rs`), but full progress heartbeats during long tool loops are still on the roadmap — see `docs/roadmap/non-web-channel-progress-events-plan.md`.
- Most chat adapters still handle one inbound message as one primary run, even if they keep typing indicators or progress pings alive.
- Subagent concurrency is intentionally bounded by `subagents.max_concurrent`, `subagents.max_active_per_chat`, timeout settings, and spawn-depth limits.
- Parallel tool execution stops at the wave boundary: a ReadOnly wave runs in parallel, but the model is still called once per tool-loop iteration.

## About binary size

The 30 MB binary size is mostly orthogonal to this question.

- a single binary can still be highly concurrent
- a small binary can still serialize all useful work through one blocking lane

For MicroClaw, the real architecture question is whether expensive work is isolated into independent async lanes or background runs. That part is already in place, even without splitting the product into many deployables.

## Practical guidance

If you want the most non-blocking behavior today:

- prefer the Web UI or Web operator API for streaming status
- offload longer work with `sessions_spawn` and let `subagents_orchestrate` coordinate fan-out
- keep `enable_mid_turn_injection: true` so follow-ups do not wait for `end_turn`
- raise `parallel_tool_max_concurrency` if your workload involves many independent ReadOnly tool calls in one turn
- use `tool_concurrency_overrides` to promote MCP tools you know are read-only into the parallel wave
- tune `subagents.max_concurrent`, `subagents.max_active_per_chat`, and `subagents.run_timeout_secs`
- raise `chat_turn_queue_max_pending` if a single chat reliably sees many follow-ups during one turn

## Status of the #307 umbrella roadmap

Issue #307 was kept open as an umbrella for the broader concurrency direction. The four bullets called out in that thread now map as follows:

| Roadmap bullet | Status | Reference |
|---|---|---|
| Safer parallelism within a single turn | Shipped | `src/tool_executor.rs`, PR #320 |
| Mid-turn responsiveness (the nanobot midturn suggestion) | Shipped, default on | `src/agent_engine.rs` mid-turn injection, PR #330 |
| Stronger parent/child contracts for orchestration-heavy subagent flows | Shipped | `subagents_orchestrate`, `subagents_focus`, `subagents_send` in `src/tools/subagents.rs` |
| Richer progress events outside the web channel | First slice shipped: concurrent event tap and mid-turn injection ack on Telegram, Discord, Slack, Matrix, Feishu, WeChat (`src/channels/event_tap.rs`). Full progress heartbeats during long tool loops still tracked. | `docs/roadmap/non-web-channel-progress-events-plan.md` |
| Deeper thread-bound routing and fan-out/fan-in for subagents | Partially in place via subagent orchestrate; further work folded into the progress-events plan above | same plan doc |

With the first three bullets shipped and the remaining work tracked under a focused plan doc, the umbrella issue can be closed. New concurrency work should land against the focused tracker rather than re-opening the umbrella.
