---
id: sdk-quickstart
title: SDK quickstart
description: Run a MicroClaw agent from a Rust application and consume its result.
---

# SDK quickstart

This path embeds the complete MicroClaw Agent Engine and keeps configuration in
your application. It requires Rust 1.93 or newer and a Tokio runtime.

## 1. Add dependencies

Until the first crates.io release, depend on the repository:

```toml title="Cargo.toml"
[dependencies]
microclaw-sdk = { version = "0.3", features = ["full"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

After publication, the SDK dependency becomes:

```toml
microclaw-sdk = { version = "0.3", features = ["full"] }
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
    Ok(())
}
```

Set `OPENAI_API_KEY`, then run the application with `cargo run`. The API key
stays owned by the host application; it does not need to be written to a
MicroClaw configuration file.

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
