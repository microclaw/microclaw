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

Install the signed and notarized stable macOS application through Homebrew:

```sh
brew tap microclaw/tap
brew install --cask microclaw-work
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
configured provider and model without showing credentials. **Settings** opens a
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

Model Settings includes quick choices for popular providers and current
recommended model IDs sourced from the same preset catalog as Server setup.
Selecting a provider fills its recommended model and endpoint; Provider, Model
ID, and Base URL remain editable so less common and custom OpenAI-compatible
services are not excluded.

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

Model onboarding uses one **Save & Test** action. It persists the settings and
runs a connection test off the GPUI thread through the same
provider implementation used by the Agent Engine, times out after 20 seconds,
and reports provider, model, latency, and a bounded visible response. Saved
credentials are never loaded into the UI and are explicitly removed from
diagnostic errors before display. A successful response exposes **Start
Chatting** so the first-use journey returns directly to the composer.

The same native **Settings** page manages agent identity and durable context.
The **Agent** section edits the active local `SOUL.md`, its file path, and the
directory containing shared project-context Markdown files. These values use
the normal MicroClaw configuration and Agent Engine loading paths, so Server
configuration and channel-specific SOUL overrides continue to work unchanged.

When an existing Codex login is detected through the presence of its auth file
or access-token environment, Model Settings offers **Use Codex Account**. Work
does not read the auth payload or copy a token into its config. It uses the
non-secret model selected in the local Codex `config.toml` when available, then
runs the same Save & Test journey. This avoids assuming that the Server's
fallback Codex model is enabled for every ChatGPT account.

Codex Responses streaming is normalized at the shared provider boundary. If a
terminal `response.done` event omits output items, visible
`response.output_text.delta`/`done` text is retained and delivered to the Agent
Engine instead of producing an empty-reply completion fallback.

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
conversation. The recent-conversation rail is searchable by conversation title
or Workspace path and keeps an explicit empty-result state. Its order is stable
by creation time instead of recent clicks or saves, and explicit Pin / Unpin
controls keep important conversations above the remaining history. Draft input is
persisted after a short debounce. If the desktop
process exits while a task is Running or Verifying, restart projects it as
**Interrupted** and offers **Retry** even though the sent composer is empty;
approval pauses remain resumable. Retry is a distinct application command: it
reuses the last submitted turn and Agent Engine session, retains the readable
conversation without inserting a duplicate user message, and discards stale
partial-run projections before relaunch.

If the active session or conversation index contains invalid JSON, Work keeps
the original file beside the store with a `.corrupt-*` suffix, rebuilds the
index from valid snapshots, and opens the newest recoverable conversation (or
a fresh one). The sidebar reports the recovery instead of trapping the app in
an unusable startup state.

**Stop** sends a cancellation request through the shared run-control registry.
It interrupts the real Agent Engine, including a pending model call, and waits
for the versioned `Cancelled` event; it is not a UI-only state change. A small
registration retry closes the race where a user stops immediately after
launching a run.

The packaged macOS path has been exercised against a real Codex account through
cancel, same-session retry, visible completion, a real high-risk approval and
same-session resume, Command-Q termination, and relaunch persistence. See the dated
[macOS smoke report](../../docs/reports/microclaw-work-macos-smoke-2026-08-26.md)
for the evidence and remaining acceptance work.

Work overrides Server's configured chat isolation only for its foreground
runtime instance. Tools, project context, checkpoint creation, diff collection,
and completion verification all resolve to the project folder explicitly
selected in the desktop conversation. Server retains its configured shared or
per-chat directory behavior.

High-risk tool requests carry a dedicated Work caller context and remain in the
approval state even when the Agent's current turn ends with explanatory text.
**Approve once** submits the one-time approval into the same persisted runtime
session and projects the resumed run. **Always allow** remains an explicit,
separate per-chat choice; CLI headless execution keeps its non-interactive
behavior.

The conversation view keeps structured, bounded projections for tool activity,
file changes, subagents, and the final response. The collapsible Details
inspector holds Plan, Process Output, and Changes / Artifacts so chat remains
the primary canvas. Its Changes / Artifacts section
supports multiple changed files, durably remembers the selected file, renders
bounded unified diffs with addition/removal highlighting, and keeps safe file
opening beside accept/revert controls placed before the diff so they remain
reachable in a compact macOS window. Tool starts and results are paired
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
`debug` for a Server-style LTO build, or `work-release` for the official desktop
distribution profile. Development bundles are ad-hoc signed for
local execution. The bundle icon is generated from the same `logo.png` used by
the documentation website. Build and verify an ad-hoc signed DMG preview with:

```sh
scripts/build_work_macos_dmg.sh work-release
scripts/smoke_work_macos_app.sh work-release
```

For a Developer ID-signed local release candidate, set an installed identity:

```sh
MICROCLAW_WORK_SIGNING_IDENTITY='Developer ID Application: <name> (<team-id>)' \
  scripts/build_work_macos_dmg.sh work-release
```

For a public distribution candidate, also provide a `notarytool` keychain
profile created with `xcrun notarytool store-credentials`:

```sh
MICROCLAW_WORK_SIGNING_IDENTITY='Developer ID Application: <name> (<team-id>)' \
MICROCLAW_WORK_NOTARY_PROFILE='microclaw-work-notary' \
  scripts/build_work_macos_dmg.sh work-release
```

The release path enables Hardened Runtime, requests trusted timestamps,
submits both the application and disk image to Apple, staples their tickets,
and validates the finished DMG. Auto-update remains later release work.

macOS is the only current product, CI, packaging, and release-acceptance target.
Windows and Linux support is deferred; dormant experimental build helpers do
not represent supported products or release commitments.

`work-release` is the canonical desktop distribution profile. It keeps release
optimization and symbol stripping but disables Thin LTO and uses parallel code
generation without changing the Server release profile.
This is a deliberate product boundary, not a debug or compatibility build.

Extended CI checks Work only on the current GitHub-hosted macOS runner. It runs
the framework-independent session and process-recovery tests, Cargo check and
Clippy for the GPUI application, builds the branded DMG, launch-smokes the
packaged application, and uploads a short-lived preview. Stable releases add
Developer ID signing, notarization, stapling, and Homebrew Cask publication.
Server CI remains independent and continues to cover Ubuntu, macOS, and Windows.

Primary controls expose native AccessKit roles and stable labels. The chat
composer is named `Message MicroClaw Work` (or active-task guidance while a run
is in progress). It is an auto-growing native textarea: Return invokes Send or
sends steering to the active run, while Shift-Return inserts a new line.
Persisted messages are paragraphs, streamed output is a status region, and
approvals are alerts. macOS release acceptance still requires direct VoiceOver
and real Pinyin IME composition evidence. Forward Tab traversal has been
visually verified from the composer through enabled actions, including skipping
disabled controls, and Shift-Tab reverses that path.

The composer receives focus after the first window frame is mounted, so a new
macOS launch can accept typing immediately instead of leaving focus on the
window root.

The native application menu provides standard Edit commands and a real
**Quit MicroClaw Work** action. Command-Q exits the GPUI process on macOS rather
than leaving an old desktop process alive. Closing the last window keeps the
application available in the Dock; launching the running app again recreates
the conversation window from durable state. Command-N creates a chat,
Command-L returns focus to the active composer, Command-Comma opens Model
Settings, and Command-Shift-D opens Diagnostics; the same actions are available
from the native menu bar.

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

The current macOS milestone still requires real-machine validation for Chinese
IME composition, VoiceOver navigation, GPU compatibility, notarized release
packaging, and sustained daily use. Real provider first response, cancellation,
retry, restart recovery, selected-project tools, diff/revert, and high-risk
approval already have dated live evidence in the macOS smoke report. Windows
and Linux release validation belongs to a later milestone.

The workspace uses Rust 1.95 because the pinned GPUI revision relies on stable
standard-library APIs that are unavailable in Rust 1.93.
