# MicroClaw Work Phase 1 application-boundary report

Status: **In progress** · Date: **2026-08-25**

This report records the first Phase 1 increment from the active
[`MicroClaw Work proposal`](../roadmap/microclaw-work-proposal-cn.md).

## Change

The framework-independent Work model moved out of the GPUI package into a new
workspace crate:

```text
apps/microclaw-work
  GPUI views, input, timers, platform data path, native packaging
                  |
                  v
crates/microclaw-work-app
  task lifecycle, plan, events, approval, snapshot, persistence
                  |
                  v
future shared agent-runtime application service
```

The desktop crate no longer defines a library or owns Work lifecycle policy.
It renders `microclaw-work-app` projections and translates UI actions into
domain commands. Timed synthetic events remain in the desktop spike only until
the production runtime event source replaces them.

## Dependency evidence

`cargo tree -p microclaw-work-app --depth 1 --locked` contains only:

- `serde`;
- `serde_json`;
- `tempfile` as a development dependency.

It contains no GPUI, platform, channel, provider, or Server dependency.

## Verification

```text
cargo test -p microclaw-work-app --locked                         4 passed
cargo clippy -p microclaw-work-app --all-targets -- -D warnings passed
cargo check -p microclaw-work --locked                           passed
cargo clippy -p microclaw-work --all-targets -- -D warnings     passed
cargo check -p microclaw --lib --locked                          passed
```

## Next boundary work

- Introduce explicit Work commands and projection update results instead of
  calling snapshot mutation methods directly from GPUI listeners.
- Define a provider-neutral runtime event envelope shared by Server and Work.
- Add a headless Work harness that runs the same command/event path without
  linking GPUI.
- Identify the smallest existing Agent Engine surface that can execute one
  prompt without importing channel startup or Web management code.
- Replace synthetic desktop events with an application-service port backed by
  the shared runtime.

The existing provider-neutral Agent Engine must not be copied into this crate.
