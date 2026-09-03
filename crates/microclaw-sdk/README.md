# MicroClaw SDK

`microclaw-sdk` is the supported facade for embedding the MicroClaw run lifecycle in a Rust
application. It exposes provider-neutral requests, events, controls, terminal results, Agent
handles, and Worker contracts without pulling in Server, channel, Web, or desktop UI code.

Minimal and standard applications supply a `RunExecutor`. The `full` preset exposes
`microclaw-engine`, including the configured `HeadlessRuntime`, so an application can start the
same skilled Agent Engine used by Server and Work without depending on either product package.

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

Use `microclaw.skills()` to list available and unavailable Skills with diagnostics. See
`examples/minimal_agent.rs` for a custom executor and `examples/configured_skilled_agent.rs` for
the full configured Agent Engine.
