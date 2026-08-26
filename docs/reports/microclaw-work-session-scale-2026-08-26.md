# MicroClaw Work session scale baseline — 2026-08-26

Status: **passed local baseline**

This report measures the durable Work-session boundary after progressive chat
rendering and bounded diff previews were introduced. It is a reproducible local
storage benchmark, not a claim about end-to-end model or tool latency.

## Fixture

The fixture uses every current product limit at once:

- 200 conversation messages with 4,000-character bodies;
- 200 projected events;
- 100 tool activities;
- 50 process activities with approximately 20 KB of output each; and
- 50 file changes with 200 KB diff payloads each.

The resulting version-13 session snapshot is 12,240,195 bytes. The benchmark
asserts that all bounded collections survive the save/load round trip and
removes its exact temporary file after each run.

## Environment and results

- macOS 27.0 (26A5416b), arm64
- Rust 1.95.0
- unoptimized development profile
- five warm runs after compiling the example

| Metric | Minimum | Median | Maximum |
| --- | ---: | ---: | ---: |
| Atomic save | 272.01 ms | 281.52 ms | 292.60 ms |
| Load and deserialize | 55.93 ms | 56.86 ms | 58.41 ms |

The local acceptance budget is 500 ms for a maximum-size atomic save and 150 ms
for load. Every measured run stayed within both budgets. Normal sessions are
substantially smaller, while the native UI initially constructs only the latest
60 messages and at most 400 lines of the selected diff.

## Reproduce

```sh
cargo run -p microclaw-work-app --example session_scale --locked
```

This baseline does not replace direct scrolling, VoiceOver, IME, or seven-day
daily-use acceptance. It proves that the supported durable upper bound can be
saved and restored without data loss or a terminal workaround.
