---
id: embedding-rust
title: Embed MicroClaw in Rust
sidebar_position: 10
---

# Embed MicroClaw in Rust

`microclaw-sdk` is the supported facade for adding MicroClaw's run lifecycle to
another Rust application. It keeps Server, Web, concrete channel adapters, and
desktop UI code outside the dependency graph.

## Choose a preset

| Preset | Includes | Best for |
|---|---|---|
| `minimal` | Stable contracts and a custom `RunExecutor` | Small hosts that provide their own execution backend |
| `standard` | The default Runtime facade | Applications that want MicroClaw lifecycle and control semantics |
| `full` | Runtime plus the configured Agent Engine | Applications that need providers, Skills, tools, memory, MCP, hooks, and Subagents |

The SDK crates are currently consumed from the repository and are not yet
published separately on crates.io:

```toml
[dependencies]
microclaw-sdk = { git = "https://github.com/microclaw/microclaw", features = ["full"] }
```

## Run a skilled Agent

```rust
use microclaw_sdk::engine::{config::Config, headless::HeadlessRuntime};
use microclaw_sdk::{AgentProfile, RunRequest};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let config = Config::load_from_path_for_headless(
    std::path::Path::new("microclaw.config.yaml"),
)?;
let runtime = HeadlessRuntime::load(config)
    .await?
    .into_embedded_runtime("my-app", 2)?;
let agent = runtime.agent(AgentProfile {
    name: "repository-reviewer".into(),
    skills: vec!["code-review".into()],
    ..AgentProfile::default()
});
let mut run = agent.run(RunRequest::new("Review this repository"));
while let Some(event) = run.next_event().await {
    println!("{}: {:?}", event.sequence, event.event);
}
println!("{}", run.result().await?.final_text);
# Ok(())
# }
```

An `AgentProfile` controls identity, prompt, selected Skills, and tool policy.
Each `RunHandle` provides ordered events, cancellation, steering, approval
controls, and one terminal result. Local Workers use the same contracts; the
versioned serializable Worker protocol leaves room for a future remote
transport without changing Agent or session identity.

See the complete compiling examples in
[`crates/microclaw-sdk/examples`](https://github.com/microclaw/microclaw/tree/main/crates/microclaw-sdk/examples)
and the [architecture guide](./architecture).
