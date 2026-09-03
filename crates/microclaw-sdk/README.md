# MicroClaw SDK

`microclaw-sdk` is the supported facade for embedding the MicroClaw run lifecycle in a Rust
application. It exposes provider-neutral requests, events, controls, terminal results, Agent
handles, and Worker contracts without pulling in Server, channel, Web, or desktop UI code.

An application supplies a `RunExecutor`. MicroClaw's product packages provide the full Agent
Engine executor; small integrations and tests can provide their own executor.

See `examples/minimal_agent.rs` for a complete runnable integration.
