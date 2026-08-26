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
