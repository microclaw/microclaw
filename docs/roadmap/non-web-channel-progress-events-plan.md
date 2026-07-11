# Non-Web Channel Progress Events — Implementation Plan

## Problem

On Telegram / Discord / Slack / Feishu / WeChat, the bot goes silent during long tool-loop turns. Users see only a typing indicator (every 4s) and nothing else until `end_turn`. When `enable_mid_turn_injection` fires, users have no feedback that their follow-up was received.

### Root cause

Telegram's "streaming" is actually post-hoc replay, not live streaming. See `src/channels/telegram.rs:1117-1148`:

```rust
let (event_tx, mut event_rx) = unbounded_channel();
process_with_agent_with_events_guarded(..., Some(&event_tx), ...).await  // runs entire turn
drop(event_tx);
// event_rx is drained *here*, replaying all buffered events as edits
```

Events are emitted in real time by the agent loop, but the receiver only starts consuming them after `.await` returns. The other non-web channels follow the same pattern.

## Goal

Give users on non-web channels real-time feedback during long turns:
1. Acknowledge mid-turn message injection when it happens
2. Show incremental progress during long tool loops
3. Avoid spamming short turns and group chats

## Phases

### Phase 0 — Baseline and guardrails (~0.5 day)

- Confirm current behavior with `enable_streaming: true` across private/group, `inline`/`separate_message` reasoning modes.
- Add a comment on `send_streaming_response` noting it is post-hoc replay, to prevent regressions.
- Add a regression test: long tool loop + `MidTurnInjection` event, assert no outbound message is sent before `end_turn` today (locks current behavior until Phase 1 flips it).

### Phase 1 — Concurrent event consumption (shipped)

Implemented as `src/channels/event_tap.rs::EventTap` — a small dedicated-task helper that owns the agent's `event_rx`, runs an optional async callback on each event, and forwards events to a replay channel so existing post-hoc consumers (e.g. `send_streaming_response` in Telegram) keep working without any change to their drain pattern.

Decision diff from the original plan:

- We did not introduce a `ChannelProgressSink` trait. The set of shared signals across channels is currently small (just the injection ack and a `send_message` tool flag), and each channel already has its own send primitives. A shared trait would be more abstraction than the call sites need today. If Phase 3 (heartbeat) adds an `update_progress` axis we can revisit and extract the trait then.
- Streaming consumers (`send_streaming_response` in Telegram, `send_matrix_streaming_response` in Matrix) now read from `tap.replay_rx` instead of the raw `event_rx`. The forwarder preserves event order and still returns `None` once the agent's senders are dropped, so the streaming UI behaves identically.

### Phase 2 — Mid-turn injection echo (shipped)

Implemented as a shared concurrent tap (`src/channels/event_tap.rs`) reused by Telegram, Discord, Slack, Matrix, Feishu, and WeChat. The tap consumes `AgentEvent`s concurrently with the agent loop, fires a per-channel callback on `MidTurnInjection { count }`, and forwards every event to a replay channel so existing post-hoc consumers (Telegram streaming, `send_message` tool detection, ...) keep working unchanged.

The actual implementation diverged from the original design in two ways:

- A single global config flag — `mid_turn_injection_echo: bool` (default `true`) — replaces the per-channel/private/groups matrix. If operators need finer control they can disable it globally; per-channel split can be added later if real usage shows group noise.
- Message copy lives in `event_tap::mid_turn_injection_ack_text` rather than `microclaw-core::text` because it is only consumed by channel-side acks today. If more shared copy grows it can move into core.

Feishu's existing concurrent progress task in topic-progress mode picks up the ack as an additional progress line (still goes through the same edit-rate budget).

### Phase 3 — Progress heartbeat (shipped)

Implemented in `src/channels/event_tap.rs` as `EventTap::spawn_with_progress`
(`ProgressConfig` + `ProgressEmit` callback). The tap subscribes to
`AgentEvent::Iteration` / `AgentEvent::ToolStart`, throttles to
`update_interval_seconds` (floor 5s), stays silent for turns shorter than
`min_turn_seconds`, and emits a terminal "✅ Done" edit only if a heartbeat was
actually shown. Copy lives in `progress_text` / `progress_done_text`
("⏳ Working — step N, using `tool`…"). Content priority diverged from the
original design: the todo-list source was dropped for now (last tool name +
iteration count proved sufficient and avoids a DB read per heartbeat).

Config (per channel, default off; groups additionally gated by `groups: true`):

```yaml
channels:
  telegram:
    progress_updates:
      enabled: true
      min_turn_seconds: 30          # don't emit for short turns
      update_interval_seconds: 20   # throttle (≤ 3/min, well under Telegram's 20/min edit cap)
```

First trigger sends the working message and captures its id; subsequent heartbeats edit in place; on `end_turn` the message is terminal-edited to "✅ Done".

### Phase 4 — Port to other channels (partially shipped)

| Channel | Edit API | Status |
|---|---|---|
| Telegram | `editMessageText` | **shipped** (`telegram.rs`, send-then-edit via stored `MessageId`) |
| Discord | `channel.edit_message` | **shipped** (`discord.rs`, DM-gated unless `groups: true`) |
| Slack | `chat.update` | **shipped** (`slack.rs`, new `post_slack_message_ts` + `update_slack_message` helpers) |
| Feishu | `im.v1.message.update` | deferred — topic-progress mode already provides a concurrent progress line |
| Matrix | `m.replace` edits | deferred |
| WeChat | none | deferred — needs `progress_updates.mode: append` fallback |

Throttle/turn-length behavior is covered by unit tests in `event_tap.rs` (`progress_heartbeat_throttles_and_finalizes`, `short_turns_stay_silent`); per-channel emit closures are thin wrappers around existing send/edit primitives.

### Phase 5 — Observability and docs (~0.5 day)

- Metrics: `agent.turn_duration_ms`, `channel.progress_updates_sent` (if metrics layer is wired up).
- Update `docs/operations/concurrency-and-responsiveness.md`.
- Update `microclaw.config.example.yaml`.
- Add a "Key patterns" entry in `CLAUDE.md`: *"Non-web channels consume AgentEvents concurrently with the agent loop via ChannelProgressSink."*

## Risks and decision points

1. **Phase 1 refactor touches the critical path** — lock current behavior with regression tests before editing.
2. **Telegram edit rate limit (20/min)** — default `update_interval_seconds: 20` gives 3/min, well within budget.
3. **Group chat UX** — all new features default off for groups.
4. **Message ordering** — when progress message (edited) + injection echo (new message) + final output (new message or edit-of-progress) coexist, the order must be stable. Recommended layout:
   - Progress message at top (editable)
   - Injection echoes appended below as new messages
   - Final output appended as new message, or terminal-edit of the progress message
5. **Interaction with `separate_message` / `inline` reasoning modes** — needs explicit verification.

## Rollout

```
Phase 0  →  Phase 1 (must land first)  →  Phase 2  →  ship & collect feedback  →  Phase 3  →  Phase 4  →  Phase 5
```

After Phase 2 the "my message was swallowed" anxiety is resolved. Ship at that point, then decide Phase 3 priority based on real usage.

## Estimate

~5 working days total. Phase 1 carries the largest uncertainty — reserve 0.5 day of buffer.

## Related

- Issue #307 — tracking umbrella for the broader concurrency roadmap. This plan implements the *"more consistent progress events across non-web channels"* bullet from the comment posted on 2026-04-21.
- #330 — mid-turn message injection (already merged). This plan builds on `AgentEvent::MidTurnInjection`, which was added as part of #330.
