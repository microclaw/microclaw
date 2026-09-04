# MicroClaw SDK

`microclaw-sdk` is the supported facade for embedding the MicroClaw run lifecycle in a Rust
application. It exposes provider-neutral requests, events, controls, terminal results, Agent
handles, and Worker contracts without pulling in Server, channel, Web, or desktop UI code.

The `minimal` preset is protocol-only, `standard` adds a host-provided `RunExecutor`, and `full`
starts the same skilled Agent Engine used by Server and Work without exposing either product package.
`minimal` does not compile the Agent Engine, HTTP clients, SQLite, Tokio, Typst, or OpenTelemetry.

## Choose a feature set

| Feature | Use it when |
|---|---|
| `minimal` | Your application only needs stable protocol, event, control, and Worker wire contracts |
| `standard` (default) | Your application wants the Runtime, Agent, Run, control, and Local Worker lifecycle |
| `remote-worker` | The host or executor communicates over the authenticated WebSocket Worker protocol |
| `full` | You want the configured MicroClaw Agent Engine, including providers, tools, memory, Skills, MCP, hooks, and Subagents |

Most first-time integrations should use `full`. The workspace minimum supported
Rust version is 1.93.

The `full` preset provides a stable builder and validates selected Skills before a run starts:

```rust,no_run
use microclaw_sdk::MicroClaw;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let microclaw = MicroClaw::builder("microclaw.config.yaml")
    .caller_channel("my-app")
    .max_concurrent_runs(4)
    .build()
    .await?;
let agent = microclaw
    .agent("reviewer")
    .skill("code-review")
    .build()?;
let result = agent.run("Review this repository").result().await?;
println!("{}", result.final_text);
# Ok(())
# }
```

Applications that do not have a MicroClaw YAML file can configure the provider directly:

```rust,no_run
use microclaw_sdk::{FullRuntimeConfig, MicroClaw};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let config = FullRuntimeConfig::new("openai", "gpt-5", std::env::var("OPENAI_API_KEY")?);
let microclaw = MicroClaw::configure(config).build().await?;
# Ok(())
# }
```

Use `microclaw.skills()` to list available and unavailable Skills with diagnostics. See
`examples/minimal_protocol.rs` for protocol-only integration, `examples/custom_executor.rs` for a
host executor, and `examples/configured_skilled_agent.rs` for the full configured Agent Engine.

## Runtime contract

- Build one `MicroClaw` runtime and reuse it across Agents.
- Use an Agent profile for stable identity, prompt, Skills, and tool policy.
- Treat each `RunHandle` as one execution with ordered events, controls, and one
  authoritative terminal `RunResult`.
- Branch on `RuntimeErrorCode` rather than parsing error messages.
- Preserve event sequence numbers when projecting runs into a UI or protocol.
- Call `Runtime::shutdown().await` to stop accepting work and drain active runs.

## Workers

`LocalWorker` uses the same Agent, Run, event, and control contracts. It exposes active and queued
capacity, labels, health, draining, resume, and `wait_for_idle()` for graceful application
shutdown. `Worker::submit` returns an explicit `Unavailable` error while draining or unavailable.
The serialized `WorkerCommand` and `WorkerFrame` types use `WORKER_PROTOCOL_VERSION` for remote
transports. Implement `WorkerTransport` and `WorkerConnection`, then call
`RemoteWorker::connect(...)`; remote runs return the same `RunHandle` used by local execution. The
`remote-worker` feature (included by `full`) provides `WebSocketWorkerTransport` and an
authenticated `WorkerHost` for real network execution.

## Guides

- [SDK overview](https://microclaw.org/docs/sdk)
- [Quickstart](https://microclaw.org/docs/sdk-quickstart)
- [Agents, runs, events, and controls](https://microclaw.org/docs/sdk-concepts)
- [Skills in embedded applications](https://microclaw.org/docs/sdk-skills)
- [Local and remote Workers](https://microclaw.org/docs/sdk-workers)
- [Features and crate boundaries](https://microclaw.org/docs/sdk-features)
