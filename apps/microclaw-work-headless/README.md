# MicroClaw Work Headless

This executable proves that the Work application projection does not depend on
GPUI. It consumes the same provider-neutral runtime events emitted by
MicroClaw Server and prints the resulting Work session snapshot.

Run the deterministic demonstration:

```sh
cargo run -p microclaw-work-headless -- demo "Inspect this workspace"
```

Or replay one JSON `RuntimeEventEnvelope` per line from standard input:

```sh
cargo run -p microclaw-work-headless -- replay "Replay a runtime task" < events.jsonl
```

This is an architectural harness, not a second agent loop.

Run a real task with the configured MicroClaw provider and the current
directory as the Work workspace:

```sh
cargo run -p microclaw-work-headless -- real "Inspect this workspace"
```

`real` initializes the existing provider-neutral Agent Engine without starting
Server channels, Web, or the scheduler. Every real Agent event is enveloped,
projected through `microclaw-work-app`, and returned as the final session JSON.
