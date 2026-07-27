# Durable Coworker Operations

MicroClaw persists interactive agent-loop progress, not only the final chat
session. A restart can therefore continue from a provider-neutral boundary
without redoing completed work.

## Checkpoint lifecycle

Each interactive chat has at most one row in `active_turns`. The row records:

- run, chat, channel, and chat type;
- phase and iteration;
- a stripped provider-neutral `Vec<Message>` snapshot;
- progress text and the names/risk of tools at an uncertain boundary;
- whether the snapshot is safe to resume;
- start and last-checkpoint timestamps.

The runtime writes these phases:

| Phase | Resumable | Meaning |
|---|---:|---|
| `starting` | no | Turn registered; no provider-neutral snapshot yet |
| `calling_llm` | yes | Message history is complete and no tool is running |
| `executing_tools` | no | One or more tools may have produced a side effect |
| `ready_for_llm` | yes | Every tool result is paired and persisted |
| `resuming` | yes | Startup recovery claimed the prior safe snapshot |

Images are removed from checkpoints to keep rows bounded. The ordinary session
store remains the source for completed conversation history.

## Startup behavior

At startup:

1. Orphaned in-process subagent runs are retired as `interrupted`.
2. Turns whose last safe checkpoint is older than 24 hours are retired rather
   than resumed.
3. A fresh resumable checkpoint is validated for complete tool-use/result
   pairing, restored to the session store, and continued automatically.
4. A non-resumable or invalid checkpoint is stopped. MicroClaw sends the last
   progress and tool summary and asks the user to verify external state.
5. Recovery decisions are written to the tamper-evident audit log as
   `turn_recovery`.

The active row is not deleted merely because startup discovered it. It remains
until the recovery reaches a terminal outcome, so another crash before the
first resumed model call does not discard the safe snapshot.

## Safety invariant

MicroClaw never claims exactly-once execution for an arbitrary external tool.
It instead guarantees:

- safe model boundaries are replayable;
- tool calls with uncertain outcomes are never replayed automatically;
- completed tool results remain paired with their tool calls;
- the user receives evidence needed to reconcile external state;
- final outbound messages use the durable delivery ledger and stable chunk
  idempotency keys.

## Observability

- `/status` shows the active durable phase, checkpoint age, pending/retrying
  delivery, and recent recovery count.
- Web UI → Governance → Durable coworker runs shows active checkpoints and
  recent `resume` / `stop_uncertain` outcomes.
- `microclaw doctor delivery` shows the outbound delivery ledger.
- Audit log kind `turn_recovery` contains phase, iteration, checkpoint time,
  and tool summary.

## Failure-injection checks

The automated regression suite covers:

```sh
cargo test -p microclaw-storage active_turn_checkpoint
cargo test checkpoint_validation_rejects_dangling_tool_use
cargo test -p microclaw-storage active_turns
```

For an end-to-end staging drill:

1. Start a task that performs a read-only tool and pause the process after the
   result is stored. Restart and verify the final response is produced once.
2. Start a task with an externally visible write and terminate the process
   while the tool is running. Restart and verify that MicroClaw reports an
   uncertain boundary instead of repeating the write.
3. Temporarily interrupt the channel during final delivery. Restore it and
   verify the delivery ledger drains without losing or reordering chunks.

Do not perform the write-boundary drill against production resources.
