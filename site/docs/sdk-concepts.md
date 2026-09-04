---
id: sdk-concepts
title: Agents, runs, and controls
description: Understand the stable lifecycle contracts exposed by microclaw-sdk.
---

# Agents, runs, and controls

The SDK separates reusable Agent configuration from one execution attempt.
This keeps identity and policy stable while allowing many independent runs.

## Lifecycle

```text
MicroClaw runtime
  └─ AgentProfile / AgentHandle
       └─ RunRequest
            ├─ ordered RuntimeEventEnvelope stream
            ├─ RunController commands
            └─ one terminal RunResult or RuntimeError
```

### Runtime

`MicroClaw` owns the configured runtime and the discovered Skill catalog. Build
it once and reuse it. `max_concurrent_runs` bounds execution admitted by that
runtime; it is not a request timeout.

### Agent

An Agent has an `AgentProfile`: name, optional system prompt, selected Skills,
and tool policy. Build separate Agent handles when identities or policies differ.

### Run

Calling `agent.run(...)` creates a `RunHandle`. A run has its own ID, request,
session identity, ordered events, controls, status, and terminal result. The
same Agent can start multiple runs subject to runtime capacity.

## Events and terminal results

Use runtime events for progressive UI and observability: text deltas, plans,
tool activity, approval requests, process updates, and lifecycle changes. Store
the sequence number when projecting events so duplicate delivery can be ignored.

Do not reconstruct the final answer from text deltas. Await `RunResult`, which
contains the authoritative final text, session ID, and terminal status.

## Controls

Clone `run.controller()` before moving the handle into an event-consumer task.
The controller can:

- cancel work;
- steer an active run with additional input;
- answer an approval request using one of the options emitted by the runtime.

Controls are requests, not proof of completion. Keep consuming events or await
the terminal result to observe the outcome.

## Error handling

Use `SdkError` and its stable `SdkErrorCode` for SDK construction and Agent validation failures. Execution
failures use `RuntimeError`, whose `code` is stable enough for application
logic. Display the message to operators, but branch on `RuntimeErrorCode`
instead of parsing strings.

## Shutdown

Call `Runtime::shutdown().await` to stop accepting new work and wait for active
and queued runs to drain. A `LocalWorker` also exposes `wait_for_idle()` when
the host manages Worker availability separately. See [Workers](./sdk-workers).
