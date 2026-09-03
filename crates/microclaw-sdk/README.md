# MicroClaw SDK

`microclaw-sdk` is the supported facade for embedding the MicroClaw run lifecycle in a Rust
application. It exposes provider-neutral requests, events, controls, terminal results, Agent
handles, and Worker contracts without pulling in Server, channel, Web, or desktop UI code.

Minimal and standard applications supply a `RunExecutor`. The `full` preset exposes
`microclaw-engine`, including the configured `HeadlessRuntime`, so an application can start the
same skilled Agent Engine used by Server and Work without depending on either product package.

See `examples/minimal_agent.rs` for a custom executor and
`examples/configured_skilled_agent.rs` for the full configured Agent Engine.
