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

The main **Send** action loads the normal MicroClaw configuration,
uses the active workspace, and streams versioned Runtime Event envelopes into
the Work projection. A new installation starts in a private, platform-local
**Work Home**, so model setup can lead directly to the first chat without a
folder-picker detour or accidental reliance on the process launch directory.
The native **Connect Project Folder** action is backed by GPUI's cross-platform
directory prompt; the canonical path survives restart. If a previously selected
project disappears, Work returns to Work Home. If Work Home itself cannot be
created, sending remains disabled until the user selects an accessible folder.

The empty chat home makes missing model configuration a primary onboarding
action and keeps project connection optional. The compact environment area at
the bottom of the chat sidebar reports the
configured provider and model without showing credentials. **Model** opens a
native, English first-run flow for provider, model, optional base URL, and API
key, so Work does not
require a terminal setup step. The API-key input is masked and marked as a
password field for accessibility/password-manager semantics; an existing key
is never loaded into the UI and a blank edit preserves it. Missing or invalid
configuration blocks real launch. **Refresh Configuration** re-reads the same
explicit Config path. This is an offline configuration check, not a provider
network probe. **Demo** remains available for UI testing without credentials.
Provider/runtime failures are shown as a terminal Work state instead of
crashing the window.

**Diagnostics** opens a native offline readiness report covering model
configuration, active-workspace writes, conversation-storage writes, and
credential-file permissions. Write probes use unique temporary files and remove
them immediately. The report never includes credentials. Provider reachability,
authentication, routing, and response decoding remain behind the explicit
**Test Provider** action so opening Diagnostics never makes a network request.
**Run First Response** is the stronger, explicitly triggered end-to-end proof:
it sends a fixed non-sensitive prompt through provider streaming and the shared
Agent Engine, consumes the versioned Work event stream, requires a visible
non-fallback completion, and reports bounded latency, event count, model, and
redacted response evidence. It uses an isolated diagnostic session and does not
duplicate the Agent Loop.

The native visual language keeps conversation primary: the quieter layered
sidebar distinguishes the active chat without rendering it as a disabled
button, the empty home offers small starter prompts, status badges use semantic
colors, and supporting setup/diagnostic surfaces use consistent cards, spacing,
and hierarchy instead of exposing a dense engineering dashboard.

Saving Model Settings keeps onboarding open and enables **Test Connection**.
The test runs off the GPUI thread, sends a minimal request through the same
provider implementation used by the Agent Engine, times out after 20 seconds,
and reports provider, model, latency, and a bounded visible response. Saved
credentials are never loaded into the UI and are explicitly removed from
diagnostic errors before display.

A packaged installation falls back to
`<platform data directory>/microclaw-work/microclaw.config.yaml`, while an
explicit `MICROCLAW_WORK_CONFIG` or discoverable shared Server config takes
precedence. Work-only configs may omit Server delivery channels. New files are
written atomically and use mode `0600` on Unix; edits preserve existing YAML
comments and retain a saved key unless the user explicitly replaces it.

Work sessions are stored as separate versioned snapshots under the application
data directory, with an atomic bounded index for the conversation list. **New
Chat** creates an independent Agent Engine conversation, and opening a recent
chat restores its matching runtime session rather than sharing a global desktop
conversation. Draft input is persisted after a short debounce. If the desktop
process exits while a task is Running or Verifying, restart projects it as
**Interrupted** and offers **Retry** even though the sent composer is empty;
approval pauses remain resumable. Retry is a distinct application command: it
reuses the last submitted turn and Agent Engine session, retains the readable
conversation without inserting a duplicate user message, and discards stale
partial-run projections before relaunch.

**Stop** sends a cancellation request through the shared run-control registry.
It interrupts the real Agent Engine, including a pending model call, and waits
for the versioned `Cancelled` event; it is not a UI-only state change. A small
registration retry closes the race where a user stops immediately after
launching a run.

High-risk tool requests remain in the approval state even when the Agent's
current turn ends with explanatory text. **Allow and Continue** submits the approve-once
reply into the same persisted runtime session and projects the resumed run.

The conversation view keeps structured, bounded projections for tool activity,
file changes, subagents, and the final response. The collapsible Details
inspector holds Plan, Process Output, and Changes / Artifacts so chat remains
the primary canvas. Its Changes / Artifacts section
supports multiple changed files, durably remembers the selected file, renders
bounded unified diffs with addition/removal highlighting, and keeps safe file
opening beside the accept/revert review controls. Tool starts and results are paired
by the shared runtime call ID instead of display order. Persisted tool inputs,
results, and diffs are secret-redacted. Artifact buttons canonicalize their
target and open it only when it exists inside the explicitly selected
workspace; missing files, absolute escapes, and symlink escapes are rejected.

Real Work runs automatically create a pre-task filesystem checkpoint through
the shared shadow-git implementation, even when Server channel configuration
has checkpoints disabled. A completed task with file changes enters explicit
review: **Accept Changes** keeps the workspace, **Revert Changes** presents a
native destructive-action confirmation and restores the checkpoint, and
the bottom composer sends a follow-up directly into the same durable
conversation and Agent Engine session. Submitted turns and unsent composer
drafts are stored separately, so sending clears the composer without erasing
the transcript or changing the thread title.
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

Extended CI continuously checks the Work application on `ubuntu-24.04`, the
current GitHub-hosted macOS runner, and `windows-latest`. Each platform runs the
framework-independent session and process-recovery tests, runs Cargo check and
Clippy for the native GPUI application, produces a release build, and uploads a
14-day preview archive. These archives are unsigned engineering previews, not release
installers. A platform is not promoted to release quality until its native
installer, signing, launch smoke test, IME/accessibility checks, and GPU/display
matrix have direct evidence.

The UI remains a workflow projection rather than an IDE. Conversation is the
primary surface, with approvals rendered inline at the point where work pauses.
Workspace, Plan, Tool Activity, bounded and redacted Process Output, File Changes,
Artifacts, runtime failures, and bounded events are persisted under the
platform-local data directory so restart recovery can be exercised.
The desktop does not contain a second Agent Loop.

Pinned upstream revisions:

- GPUI/Zed: `8b1497dbd22fb06f5838a7c0b84a1e54fafa71bc` (pinned for the
  shared Git source by this repository's `Cargo.lock`; this is the revision
  resolved by GPUI Component's own lockfile)
- GPUI Component: `d5821f270317754f2a311a0bb148ec32cbb0ced4`

Phase 0 still requires real-machine validation for Chinese IME, accessibility,
Windows/Linux rendering, GPU compatibility, release packaging, and a real
provider first-response journey.

The workspace uses Rust 1.95 because the pinned GPUI revision relies on stable
standard-library APIs that are unavailable in Rust 1.93.
