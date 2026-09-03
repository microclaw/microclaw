# MicroClaw SDK

`microclaw-sdk` is the supported facade for embedding the MicroClaw run lifecycle in a Rust
application. It exposes provider-neutral requests, events, controls, terminal results, Agent
handles, and Worker contracts without pulling in Server, channel, Web, or desktop UI code.

Minimal and standard applications supply a `RunExecutor`. The `full` preset starts the same
skilled Agent Engine used by Server and Work without exposing either product package.

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
`examples/minimal_agent.rs` for a custom executor and `examples/configured_skilled_agent.rs` for
the full configured Agent Engine.

## Workers

`LocalWorker` uses the same Agent, Run, event, and control contracts. It exposes active and queued
capacity, labels, health, draining, resume, and `wait_for_idle()` for graceful application
shutdown. `Worker::submit` returns an explicit `Unavailable` error while draining or unavailable.
The serialized `WorkerCommand` and `WorkerFrame` types use `WORKER_PROTOCOL_VERSION` for remote
transports. Implement `WorkerTransport` and `WorkerConnection`, then call
`RemoteWorker::connect(...)`; remote runs return the same `RunHandle` used by local execution. The
`remote-worker` feature (included by `full`) provides `WebSocketWorkerTransport` and an
authenticated `WorkerHost` for real network execution.
