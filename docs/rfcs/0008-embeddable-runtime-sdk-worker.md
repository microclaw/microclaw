# RFC 0008: Embeddable Runtime, SDK, and Worker Boundary

- Status: Implemented
- Owner: runtime/application
- Created: 2026-09-03

## Context

Before this extraction, MicroClaw already had one provider-neutral Agent Loop and separate crates
for foundational types, storage, tools, channels, ClawHub, observability, and Work projections.
However, the reusable Agent Loop, provider assembly, prompt construction, recovery, skills, hooks,
and tool registry lived inside the root product package. `microclaw-work-runtime` consequently
depended on the whole root `microclaw` package through `HeadlessRuntime`.

That made embedding possible but expensive and unstable: an application had to accept the Server's
concrete `Config`, `AppState`, SQLite setup, channel registry, and product defaults instead of
supplying only the capabilities it needed.

## Decision

Create four explicit public layers:

1. `microclaw-core`: stable serializable contracts and dependency-light foundational types.
2. `microclaw-runtime`: the UI- and channel-independent Agent Runtime and run lifecycle.
3. `microclaw-engine`: the concrete provider-neutral Agent Loop and default services.
4. `microclaw-sdk`: an ergonomic facade with supported defaults and feature presets.

Server, Work, headless clients, local workers, and future remote workers consume the same
`RunRequest`, `RunHandle`, `RuntimeEventEnvelope`, and `RunResult` contracts. No product surface may
implement or copy its own Agent Loop.

## Dependency Direction

```text
product apps -> microclaw-sdk -> microclaw-engine -> microclaw-runtime
                                      |                  |
                                      v                  v
                              capability crates -> microclaw-core
```

The Runtime must not depend on Axum, GPUI, Teloxide, Serenity, or channel adapters. The Engine may
depend on the channel-neutral `microclaw-channels` delivery contract, but never on concrete channel
adapters.
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

V1 makes the whole `RunExecutor` replaceable at the lifecycle boundary. The full Engine keeps its
existing provider, tool, storage, approval, event, memory, skills, hooks, and supervision seams;
those lower-level seams become stable SDK ports only when a real embedding consumer needs to
replace them. This keeps the dependency-light Runtime honest instead of copying Engine assembly.

## Worker Model

V1 implements `LocalWorker`, an in-process execution host over `microclaw-runtime`. A worker owns
capacity and execution placement; Agent identity and session identity remain independent.

The serializable worker boundary includes descriptors, capabilities, health, run submission,
runtime events, control messages, and terminal results. A later remote transport may use HTTP,
A2A, or another protocol without changing Runtime semantics.

Remote execution, distributed leasing, and exactly-once side effects are not required for the
initial extraction. They must not be simulated by process-global state.

## Feature Policy

`microclaw-runtime` keeps lifecycle contracts independent of product surfaces. Supported SDK and
Runtime feature presets are `minimal`, `standard` (the default), and `full`; the full SDK facade
adds the configured Engine and its SQLite, built-in tools, skills, MCP, ClawHub, subagents, hooks,
media, and observability services.

Only supported presets are required in CI initially. UI and channel dependencies are never Runtime
features.

## Migration

1. Add stable run, Agent, worker, error, and capability contracts to `microclaw-core`.
2. Move the concrete `AppState` and default services into `microclaw-engine`; keep per-run context,
   handles, controls, capacity, and lifecycle state in `microclaw-runtime`.
3. Extract the Agent Loop, prompt/compaction, execution, completion, control, and recovery modules
   into `microclaw-engine`, keeping lifecycle and serializable contracts in Runtime/Core.
4. Introduce `RuntimeBuilder`, `Runtime`, `AgentHandle`, and `RunHandle` and preserve temporary root
   re-exports.
5. Migrate headless, Work, and Server in that order.
6. Add `microclaw-sdk`, supported feature presets, and compiling embedding examples.
7. Add `LocalWorker`; add a remote worker transport only after the local contract is proven.
8. Keep documented root compatibility re-exports for the current release; remove them only in a
   future breaking release.

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
3. `microclaw-runtime` has no Web, channel, Engine, or GUI dependencies, and `microclaw-engine`
   has no Server, Web, concrete channel, or GUI dependencies.
4. A third-party example starts a skilled Agent and receives events in no more than roughly 50
   lines of application code.
5. Contract tests cover execution, tool pairing, recovery, compaction, cancellation, steering,
   approval, and parent/child runs across supported consumers.
6. Dependency-boundary checks run in CI.
7. Minimal, standard/default, and full feature presets compile and pass their relevant tests.
8. Existing workspace tests, Clippy, Web build, and generated documentation checks pass.

The contract coverage is intentionally layered:

| Contract | Authoritative coverage |
|---|---|
| Execution and ordered events | `microclaw-runtime::runtime_streams_events_and_returns_a_result`; `microclaw-engine::headless::reusable_runtime_executes_real_agent_loop_and_emits_envelopes` |
| Tool pairing and compaction boundary | `microclaw-engine::llm::test_sanitize_messages_removes_orphaned_tool_results`; `microclaw-engine::agent_engine::safe_compact_split_lands_on_plain_user_message` |
| Recovery | `microclaw-engine::turn_recovery::checkpoint_validation_rejects_dangling_tool_use`; workspace recovery tests |
| Cancellation and steering | Runtime control tests plus real Engine cancellation and post-tool steering tests in `headless` |
| Approval | acknowledged Runtime control tests plus Agent Engine high-risk approval/deny tests |
| Parent/child runs and Worker placement | `parent_child_identity_survives_local_worker_submission`; subagent persistence/cancellation tests in Work Runtime |
| Skills and tool policy | `embedded_agent_profile_applies_prompt_and_selected_skills`; `embedded_read_only_profile_hides_mutating_tools`; Work Skill import/toggle tests |

## Rollback

Compatibility re-exports allow individual consumers to return temporarily to the root facade.
No destructive storage migration is part of the extraction. The old entry points are removed only
after all internal consumers pass parity tests against the new Runtime API.
