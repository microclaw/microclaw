# MicroClaw Work Phase 1 application-boundary report

Status: **In progress — real Agent Engine adapter landed** · Date: **2026-08-25**

This report records the first Phase 1 increment from the active
[`MicroClaw Work proposal`](../roadmap/microclaw-work-proposal-cn.md).

## Change

The framework-independent Work model moved out of the GPUI package into a new
workspace crate:

```text
apps/microclaw-work
  GPUI views, input, timers, platform data path, native packaging
                  |
                  v
crates/microclaw-work-app
  task lifecycle, plan, events, approval, snapshot, persistence
                  |
                  v
microclaw-core::runtime_event
  provider-neutral Server/Work event protocol
```

The desktop crate no longer defines a library or owns Work lifecycle policy.
It renders `microclaw-work-app` projections and translates UI actions into
domain commands. Timed synthetic events remain in the desktop spike only until
the production runtime event source replaces them.

The application crate now exposes one explicit lifecycle reducer:

```text
WorkCommand -> WorkSessionSnapshot::apply -> CommandOutcome | WorkCommandError
```

Start, progress, approval request, approval, and reset all use this path.
Invalid state transitions are rejected in the application layer rather than
being interpreted independently by GPUI listeners.

## Shared runtime event boundary

The Server's existing `AgentEvent` definition now lives in
`microclaw-core::runtime_event::RuntimeEvent`. The root Agent Engine re-exports
that type as `AgentEvent`, so all existing Server event producers and channel
consumers continue to compile while Work consumes the exact same enum.

Transport and replay use `RuntimeEventEnvelope`, which carries:

- a protocol schema version;
- a stable runtime run ID;
- a monotonically increasing sequence;
- the provider-neutral runtime event.

The Work reducer accepts the envelope through
`WorkCommand::ApplyRuntimeEvent`. It projects tool activity, approval, file
diffs, subagents, cancellation, and completion into UI-independent Work state.
Sequence gaps and unsupported protocol versions are rejected before the
projection is mutated.

`apps/microclaw-work-headless` is a no-GPUI harness. It can run a deterministic
event stream or replay JSONL envelopes from standard input and emits the final
Work session as JSON. It proves that GPUI is one projection consumer, not the
owner of the task loop.

The root runtime now also exposes `HeadlessRuntime`, a reusable application
service extracted from the existing `microclaw run` path. It owns `AppState`,
session persistence, the existing `process_with_agent_with_events` call, and
the raw-event-to-envelope bridge. It starts no Server channels, Web server,
scheduler, or gateway. The original CLI now delegates to this service.

The harness has a `real` mode which:

1. loads the normal MicroClaw provider configuration;
2. uses the current directory as the Work workspace;
3. starts the existing provider-neutral Agent Engine;
4. projects every real envelope through `microclaw-work-app`;
5. returns the completed Work session as JSON.

An offline integration test replaces only the LLM provider with a deterministic
fake. The database, session lifecycle, Agent Engine, event emission, envelope
sequencing, and Work-facing application service remain real. This verifies the
boundary without API credentials, network access, or model cost.

## Dependency evidence

`cargo tree -p microclaw-work-app --depth 1 --locked` contains only:

- `microclaw-core` for the shared runtime event protocol;
- `serde`;
- `serde_json`;
- `tempfile` as a development dependency.

It contains no GPUI, platform, channel, provider, or Server dependency.

## Verification

```text
cargo test -p microclaw-core --locked                            51 passed
cargo test -p microclaw-work-app --locked                         7 passed
cargo test -p microclaw-work-headless --locked                    1 passed
cargo clippy -p microclaw-work-app --all-targets -- -D warnings passed
cargo clippy -p microclaw-work-headless --all-targets -- -D warnings passed
cargo check -p microclaw-work --locked                           passed
cargo clippy -p microclaw-work --all-targets -- -D warnings     passed
cargo check -p microclaw --lib --locked                          passed
cargo test -p microclaw event_tap --lib --locked                 12 passed
cargo test -p microclaw agent_engine::tests --lib --locked       43 passed
cargo test -p microclaw headless::tests --lib --locked            2 passed
cargo run -p microclaw-work-headless -- demo ...                 completed
microclaw config check                                           passed
```

A live, no-tool smoke request reached the configured external provider, but
the provider rejected the repository's configured `gpt-5.3-codex` model for
ChatGPT Account authentication with HTTP 400. This is configuration evidence,
not a completed live-run result; the report does not count it as a passing
end-to-end task. No private workspace file was sent during that request.

## Next boundary work

- Add an application-service port for starting, approving, cancelling, and
  resuming a runtime run rather than only projecting its events.
- Replace synthetic desktop events with an application-service port backed by
  the shared runtime.
- Add event persistence/replay at the Server boundary and coalesce high-rate
  text deltas before they enter the durable Work timeline.

The existing provider-neutral Agent Engine must not be copied into this crate.
