# MicroClaw Desktop Headless

This executable proves that the Desktop application projection does not depend on
GPUI. It consumes the same provider-neutral runtime events emitted by
MicroClaw Server and prints the resulting Desktop session snapshot.

Run the deterministic demonstration:

```sh
cargo run -p microclaw-desktop-headless -- demo "Inspect this workspace"
```

Or replay one JSON `RuntimeEventEnvelope` per line from standard input:

```sh
cargo run -p microclaw-desktop-headless -- replay "Replay a runtime task" < events.jsonl
```

This is an architectural harness, not a second agent loop.

Run the deterministic multi-process recovery test:

```sh
cargo test -p microclaw-desktop-headless --test recovery_process
```

The test launches the executable three times. `recovery-crash` persists a
partially streamed Running session and aborts the process; `recovery-resume`
opens the same store and projects Interrupted; `recovery-retry` applies the
first-class retry command and saves the cleaned Running projection. These modes
are test harness operations over the real `DesktopSessionStore`, not product UI or
a separate runtime.

Run a real task with the configured MicroClaw provider and the current
directory as the Desktop workspace:

```sh
cargo run -p microclaw-desktop-headless -- real "Inspect this workspace"
```

`real` initializes the existing provider-neutral Agent Engine without starting
Server channels, Web, or the scheduler. Every real Agent event is enveloped,
projected through `microclaw-desktop-app`, and returned as the final session JSON.
