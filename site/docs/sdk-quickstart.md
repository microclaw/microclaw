---
id: sdk-quickstart
title: SDK quickstart
description: Run a MicroClaw agent from a Rust application and consume its result.
---

# SDK quickstart

This path embeds the complete MicroClaw Agent Engine and keeps configuration in
your application. It requires Rust 1.93 or newer and a Tokio runtime.

## 1. Add dependencies

Use the published SDK from crates.io:

```toml title="Cargo.toml"
[dependencies]
microclaw-sdk = { version = "0.6.1", features = ["full"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## 2. Configure and run an Agent

```rust title="src/main.rs"
use microclaw_sdk::{FullRuntimeConfig, MicroClaw};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = FullRuntimeConfig::new(
        "openai",
        "gpt-5",
        std::env::var("OPENAI_API_KEY")?,
    );
    let microclaw = MicroClaw::configure(config)
        .workspace(std::env::current_dir()?)
        .caller_channel("my-rust-app")
        .max_concurrent_runs(4)
        .build()
        .await?;

    let agent = microclaw
        .agent("assistant")
        .system_prompt("Be concise and cite the files you inspect.")
        .build()?;

    let result = agent.run("Summarize this project").result().await?;
    println!("{}", result.final_text);
    microclaw.runtime().shutdown().await;
    Ok(())
}
```

Set `OPENAI_API_KEY`, then run the application with `cargo run`. The API key
stays owned by the host application; it does not need to be written to a
MicroClaw configuration file.

## Integration checklist

A first integration is complete when the host application can:

- build one `MicroClaw` value and reuse it rather than rebuilding per request;
- create an Agent profile with an explicit name and tool policy;
- consume ordered events for live progress and use `RunResult` for completion;
- classify failures through `RuntimeErrorCode` instead of matching text;
- cancel an active run and shut the Runtime down cleanly.

Start with one local Agent. Add managed Skills only after the basic run works,
and add a Worker only when the application needs queueing or isolation. This
keeps the first integration small while preserving the same API as it grows.

## 3. Stream progress

Keep the `RunHandle` mutable and read events before taking its terminal result:

```rust
let mut run = agent.run("Review this repository");
while let Some(envelope) = run.next_event().await {
    println!("{}: {:?}", envelope.sequence, envelope.event);
}
let result = run.result().await?;
```

Events are ordered by `sequence`. Treat `RunResult` as the authoritative
terminal outcome; events are the live projection for a UI, log, or protocol.

## YAML configuration instead

Applications that already use MicroClaw configuration can load it directly:

```rust
let microclaw = MicroClaw::builder("microclaw.config.yaml")
    .caller_channel("my-rust-app")
    .build()
    .await?;
```

Use `builder_from_environment()` to follow MicroClaw's normal configuration
discovery. Continue with [SDK concepts](./sdk-concepts) before wiring events and
controls into your UI.

## Common failures

| Symptom | What to check |
|---|---|
| `Unavailable` | Provider reachability, credentials, or Worker health; retry only when `retryable` is true. |
| `InvalidRequest` | Agent profile, selected Skill names, protocol version, and run identity. |
| A Skill is listed but unavailable | Read its catalog diagnostic; install its dependency or enable it before starting the run. |
| Events stop after a disconnect | Keep the same run ID and last sequence; remote Workers resume and suppress duplicates automatically. |
| Shutdown does not finish immediately | Stop accepting work, cancel or drain active runs, then await `Runtime::shutdown()`. |
