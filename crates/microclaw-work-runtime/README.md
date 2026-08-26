# MicroClaw Work Runtime

This crate is the UI-independent foreground runtime service for MicroClaw
Work. It owns the worker thread and Tokio runtime, loads the normal MicroClaw
configuration, calls the shared `HeadlessRuntime`, forwards versioned runtime
events, and routes cancellation through the shared run-control registry.

Desktop, headless, and future remote projections should depend on this service
instead of calling the Agent Engine or creating their own worker lifecycle.
The provider-neutral Agent Loop remains in the root runtime and is not copied
here.

Run its focused checks with:

```sh
cargo test -p microclaw-work-runtime --locked
cargo clippy -p microclaw-work-runtime --all-targets --locked -- -D warnings
```
