# MicroClaw Work GPUI spike

This crate is the Phase 0 desktop technology spike. It validates a pure-Rust
GPUI + GPUI Component application boundary before the shared agent runtime is
connected.

Run on a supported desktop host:

```sh
cargo run -p microclaw-work
```

Run the framework-independent session tests:

```sh
cargo test -p microclaw-work --lib
```

Build a development macOS application bundle:

```sh
scripts/build_work_macos_app.sh debug
```

The validated bundle is written to
`target/microclaw-work-app/debug/MicroClaw Work.app`. Use `release` instead of
`debug` for an optimized bundle. Development bundles are ad-hoc signed for
local execution. Developer ID signing, notarization, DMG creation, and
auto-update are later Phase 0/5 work.

The current UI is deliberately a workflow projection. It demonstrates the
intended Workspace, Plan, Approval, Diff, and Artifact surfaces and persists its
versioned spike snapshot under the platform-local data directory so restart
recovery can be exercised. A task input and bounded synthetic event stream
exercise the foreground Work lifecycle through an approval pause. It does not
yet execute the production agent loop.

Pinned upstream revisions:

- GPUI/Zed: `8b1497dbd22fb06f5838a7c0b84a1e54fafa71bc` (pinned for the
  shared Git source by this repository's `Cargo.lock`; this is the revision
  resolved by GPUI Component's own lockfile)
- GPUI Component: `d5821f270317754f2a311a0bb148ec32cbb0ced4`

Phase 0 still requires real-machine validation for Chinese IME, accessibility,
Windows/Linux rendering, GPU compatibility, packaging, and restart recovery.

The workspace uses Rust 1.95 because the pinned GPUI revision relies on stable
standard-library APIs that are unavailable in Rust 1.93.
