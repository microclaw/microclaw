# RFC 0008: Embeddable Runtime, SDK, and Worker Boundary

- Status: In Progress
- Owner: runtime/application
- Created: 2026-09-03

## Context

MicroClaw already has one provider-neutral Agent Loop and separate crates for foundational types,
storage, tools, channels, ClawHub, observability, and Work projections. However, the reusable Agent
Loop, provider assembly, prompt construction, recovery, skills, hooks, and tool registry still live
inside the root product package. `microclaw-work-runtime` consequently depends on the whole root
`microclaw` package through `HeadlessRuntime`.

This makes embedding possible but expensive and unstable: an application must accept the Server's
concrete `Config`, `AppState`, SQLite setup, channel registry, and product defaults instead of
supplying only the capabilities it needs.

## Decision

Create three explicit public layers:

1. `microclaw-core`: stable serializable contracts and dependency-light foundational types.
2. `microclaw-runtime`: the UI- and channel-independent Agent Runtime and run lifecycle.
3. `microclaw-sdk`: an ergonomic facade with supported defaults and feature presets.

Server, Work, headless clients, local workers, and future remote workers consume the same
`RunRequest`, `RunHandle`, `RuntimeEventEnvelope`, and `RunResult` contracts. No product surface may
implement or copy its own Agent Loop.

## Dependency Direction

```text
product apps -> microclaw-sdk -> microclaw-runtime -> capability crates -> microclaw-core
```

The Runtime must not depend on Axum, GPUI, Teloxide, Serenity, or concrete channel adapters.
Channel adapters translate ingress and delivery at the Server boundary. Work owns its GUI/runtime
thread bridge. A Worker is an execution host for runs; it is not an Agent identity or a Subagent.

## Public Runtime Contract

The supported embedding surface consists of:

- `RuntimeBuilder`: capability injection and validated construction;
- `Runtime`: creation and lookup of logical Agent handles;
- `AgentProfile`: identity, prompt, skills, and tool policy;
- `RunRequest`: provider-neutral input and caller/workspace context;
- `RunHandle`: event subscription, cancellation, steering, approval, and terminal result;
- `RuntimeEventEnvelope`: versioned replayable progress stream;
- `RunResult`: terminal status, response, error, and metadata.

The first replaceable service ports are `ModelProvider`, `ToolExecutor`, `SessionStore`,
`ApprovalHandler`, and `EventSink`. Memory, skills, hooks, and subagent supervision may initially
ship as Runtime-owned default services and become replaceable only when a real consumer requires
it.

## Worker Model

V1 implements `LocalWorker`, an in-process execution host over `microclaw-runtime`. A worker owns
capacity and execution placement; Agent identity and session identity remain independent.

The serializable worker boundary includes descriptors, capabilities, health, run submission,
runtime events, control messages, and terminal results. A later remote transport may use HTTP,
A2A, or another protocol without changing Runtime semantics.

Remote execution, distributed leasing, and exactly-once side effects are not required for the
initial extraction. They must not be simulated by process-global state.

## Feature Policy

`microclaw-runtime` keeps the core loop independent of product surfaces. Supported feature presets
are `minimal`, `default`, and `full`; individual capabilities may include SQLite, built-in tools,
skills, MCP, ClawHub, subagents, hooks, scheduler integration, media, and observability.

Only supported presets are required in CI initially. UI and channel dependencies are never Runtime
features.

## Migration

1. Add stable run, Agent, worker, error, and capability contracts to `microclaw-core`.
2. Split the concrete `AppState` into Runtime services, optional Runtime features, and per-run
   context while preserving behavior.
3. Extract the Agent Loop, prompt/compaction, execution, completion, control, and recovery modules
   into `microclaw-runtime`.
4. Introduce `RuntimeBuilder`, `Runtime`, `AgentHandle`, and `RunHandle` and preserve temporary root
   re-exports.
5. Migrate headless, Work, and Server in that order.
6. Add `microclaw-sdk`, supported feature presets, and compiling embedding examples.
7. Add `LocalWorker`; add a remote worker transport only after the local contract is proven.
8. Remove compatibility paths once all internal consumers and documentation use the public API.

## Compatibility

- Existing CLI flags and YAML configuration remain supported.
- Existing channel and Web behavior remains unchanged during extraction.
- Existing event JSON remains backward compatible; fields may be added but not silently renamed.
- Existing root module paths may be re-exported during migration and removed only in a documented
  breaking release.
- Database migrations remain backward compatible and non-destructive.

## Security

Injected tools still execute through one Runtime policy, approval, sandbox, hook, redaction, and
audit pipeline. An embedding API must not provide a shortcut around these controls. Caller,
principal, workspace, Agent, parent run, and worker identity remain explicit at authorization
boundaries.

## Verification and Completion Criteria

The extraction is complete only when:

1. Server, Work, and headless execution all consume the same Runtime API.
2. `microclaw-work-runtime` no longer depends on the root `microclaw` package.
3. `microclaw-runtime` has no Web, channel, or GUI dependencies.
4. A third-party example starts a skilled Agent and receives events in no more than roughly 50
   lines of application code.
5. Contract tests cover execution, tool pairing, recovery, compaction, cancellation, steering,
   approval, and parent/child runs across supported consumers.
6. Dependency-boundary checks run in CI.
7. Minimal, default, and full feature presets compile and pass their relevant tests.
8. Existing workspace tests, Clippy, Web build, and generated documentation checks pass.

## Rollback

Compatibility re-exports allow individual consumers to return temporarily to the root facade.
No destructive storage migration is part of the extraction. The old entry points are removed only
after all internal consumers pass parity tests against the new Runtime API.
