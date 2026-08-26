# MicroClaw Work Desktop

This crate is the native MicroClaw Work desktop application. It uses GPUI and
GPUI Component for the UI and consumes `microclaw-work-runtime`, the reusable
foreground application service that runs the existing provider-neutral
MicroClaw Agent Engine on a dedicated Tokio worker thread.

Work lifecycle and persistence live in the framework-independent
`microclaw-work-app` crate. Worker lifecycle, event forwarding, and
cancellation live in `microclaw-work-runtime`. This desktop package owns only
GPUI/platform adaptation and must not duplicate the provider-neutral Agent
Engine or runtime control.

Run on a supported desktop host:

```sh
cargo run -p microclaw-work
```

Run the framework-independent session tests:

```sh
cargo test -p microclaw-work-app
```

The main action, **Run Task**, loads the normal MicroClaw configuration,
uses the selected workspace, and streams versioned Runtime Event envelopes into
the Work projection. The native **Select Workspace** action is backed by GPUI's
cross-platform directory prompt; the canonical path survives restart. A new
install has no implicit workspace and cannot run until the user selects one.
Missing workspaces return to this safe unselected state instead of falling back
to the process launch directory (which can be `/` for a packaged application).

The sidebar reports the configured provider, model, and config path without
showing credentials. **Model Settings** provides a native, English first-run
flow for provider, model, optional base URL, and API key, so Work does not
require a terminal setup step. The API-key input is masked and marked as a
password field for accessibility/password-manager semantics; an existing key
is never loaded into the UI and a blank edit preserves it. Missing or invalid
configuration blocks real launch. **Refresh Configuration** re-reads the same
explicit Config path. This is an offline configuration check, not a provider
network probe. **Demo** remains available for UI testing without credentials.
Provider/runtime failures are shown as a terminal Work state instead of
crashing the window.

A packaged installation falls back to
`<platform data directory>/microclaw-work/microclaw.config.yaml`, while an
explicit `MICROCLAW_WORK_CONFIG` or discoverable shared Server config takes
precedence. Work-only configs may omit Server delivery channels. New files are
written atomically and use mode `0600` on Unix; edits preserve existing YAML
comments and retain a saved key unless the user explicitly replaces it.

Work sessions are stored as separate versioned snapshots under the application
data directory, with an atomic bounded index for the recent-task list. **New
Task** creates an independent Agent Engine conversation, and opening a recent
task restores its matching runtime session rather than sharing a global desktop
conversation. Draft input is persisted after a short debounce. If the desktop
process exits while a task is Running or Verifying, restart projects it as
**Interrupted** and offers **Retry Task**; approval pauses remain resumable.

**Stop** sends a cancellation request through the shared run-control registry.
It interrupts the real Agent Engine, including a pending model call, and waits
for the versioned `Cancelled` event; it is not a UI-only state change. A small
registration retry closes the race where a user stops immediately after
launching a run.

High-risk tool requests remain in the approval state even when the Agent's
current turn ends with explanatory text. **Allow and Continue** submits the approve-once
reply into the same persisted runtime session and projects the resumed run.

The task view keeps structured, bounded projections for tool activity, file
changes, subagents, and the final response. Tool starts and results are paired
by the shared runtime call ID instead of display order. Persisted tool inputs,
results, and diffs are secret-redacted. Artifact buttons canonicalize their
target and open it only when it exists inside the explicitly selected
workspace; missing files, absolute escapes, and symlink escapes are rejected.

Real Work runs automatically create a pre-task filesystem checkpoint through
the shared shadow-git implementation, even when Server channel configuration
has checkpoints disabled. A completed task with file changes enters explicit
review: **Accept Changes** keeps the workspace, **Revert Changes** presents a
native destructive-action confirmation and restores the checkpoint, and
**Continue Task** opens a follow-up prompt in the same Agent Engine session.
Restore handles empty workspaces, modified/deleted tracked files, and new
non-ignored files. Existing ignored files such as `.env` and nested repositories
remain protected. Checkpoint and restore work runs off the GPUI thread.

Build a development macOS application bundle:

```sh
scripts/build_work_macos_app.sh debug
```

The validated bundle is written to
`target/microclaw-work-app/debug/MicroClaw Work.app`. Use `release` instead of
`debug` for an optimized bundle. Development bundles are ad-hoc signed for
local execution. Developer ID signing, notarization, DMG creation, and
auto-update are later Phase 0/5 work.

The UI remains a workflow projection rather than an IDE. Workspace, Plan,
Approval, Tool Activity, File Changes, Artifacts, runtime failures, and bounded events are persisted
under the platform-local data directory so restart recovery can be exercised.
The desktop does not contain a second Agent Loop.

Pinned upstream revisions:

- GPUI/Zed: `8b1497dbd22fb06f5838a7c0b84a1e54fafa71bc` (pinned for the
  shared Git source by this repository's `Cargo.lock`; this is the revision
  resolved by GPUI Component's own lockfile)
- GPUI Component: `d5821f270317754f2a311a0bb148ec32cbb0ced4`

Phase 0 still requires real-machine validation for Chinese IME, accessibility,
Windows/Linux rendering, GPU compatibility, packaging, and restart recovery.

The workspace uses Rust 1.95 because the pinned GPUI revision relies on stable
standard-library APIs that are unavailable in Rust 1.93.
