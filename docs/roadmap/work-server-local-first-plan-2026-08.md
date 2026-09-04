# MicroClaw Server + Work local-first plan

Status: **Superseded by the v0.6.0 execution plan**
Updated: **2026-09-04**

> MicroClaw Server is a cross-platform, deployable Agent Runtime. MicroClaw
> Work is a native, local-first desktop coworker built on the same core.

This is the canonical plan for the next MicroClaw product phase. It replaces
the narrower macOS execution plan as the active roadmap while preserving
macOS as Work's only fully supported desktop platform. Linux and Windows Work
builds remain portable previews; MicroClaw Server remains supported on macOS,
Linux, and Windows.

## Product boundary

```text
MicroClaw Server                         MicroClaw Work
always-on channels, APIs, schedules      foreground local conversations
Web operator and remote automation       native GPUI workspace and review
macOS / Linux / Windows                  macOS supported; Linux/Windows preview
                  \                     /
                   shared Rust runtime
       Agent Engine · providers · tools · policy · memory
          skills · MCP · checkpoints · runtime events
```

Work is not a WebView distribution of the Server console. The desktop bundle
does not embed the React application. GPUI owns presentation and native input;
`microclaw-work-app` owns framework-independent commands and projections;
`microclaw-work-runtime` bridges those commands through `microclaw-sdk` to the shared Agent Engine.
There is one provider-neutral Agent Loop.

## Delivery tracks

### 1. macOS product completeness

Goal: a new user can install Work, configure it, finish a real project task,
review the result, recover from interruption, and update or uninstall without
using a terminal for normal operation.

Delivered baseline:

- signed, notarized, stapled Apple Silicon DMG and Homebrew Cask;
- conversation-first GPUI UI, native menu and shortcuts, system/light/dark
  appearance, model onboarding, local Soul and project-context settings;
- durable chats, search, creation-time ordering, right-click pinning, drafts,
  restart recovery, cancellation, retry, steering, diagnostics, and explicit
  provider tests;
- native in-app and operating-system notifications for completed and failed
  tasks, excluding approval pauses and deliberate cancellation;
- bounded long-thread, diff, process-output, and artifact projections;
- branded bundle, app icon, release verification, and local Cask lifecycle.

Acceptance gate:

- clean macOS account install, first task, upgrade, and uninstall evidence;
- seven consecutive days of daily use without conversation loss, unsafe
  mutation, or a required terminal workaround;
- VoiceOver speech pass for the primary journey;
- update discovery and release handoff remain visible inside Settings.

### 2. Server and Work share one kernel

Goal: product-specific code adapts inputs, lifecycle, and presentation without
forking model or tool behavior.

Required invariants:

- `crates/microclaw-engine/src/agent_engine.rs` remains the only conversation/tool-use loop;
- provider translation remains in the shared LLM boundary;
- Work launches through `microclaw-work-runtime`, never directly from a GPUI
  view into provider or tool implementations;
- Work commands and persisted projections remain UI-independent in
  `microclaw-work-app`;
- Server channel, API, Web, scheduling, and delivery tests remain unchanged by
  desktop releases.

Acceptance gate: focused Work tests and the complete Server workspace matrix
pass from the same commit, and dependency checks show no React/Web assets in
the Work bundle.

### 3. local-first Workspace and task loop

Goal: Work is useful without an account or Server connection.

The primary journey is:

```text
choose a folder -> describe work -> inspect plan and activity
-> approve side effects -> review files, diff, verification, and artifacts
-> accept, revise, or restore -> continue in the same conversation
```

Delivered baseline includes a private Work Home fallback, canonical folder
selection, per-conversation Workspace persistence, file and symlink escape
protection, shared tool guardrails, pre-task checkpoints, multi-file review,
safe artifact opening, accept/revert, and same-session follow-up. Work also
shows local project identity and Git branch context, labels its current-folder
access boundary, and accepts up to eight Workspace files through the native
picker or drag and drop. Attachments persist as relative paths, appear in the
conversation, and are passed to the shared Agent Engine without copying file
contents into desktop state; outside-Workspace files are rejected.

Next depth remains deliberately smaller than an embedded IDE: richer
repository-change orientation, recent projects, file reveal from attachment
chips, and stronger background-task visibility. Local execution remains the
default; connecting a user-owned Server is optional and belongs to a later
phase.

### 4. Main Agent, Subagents, and Skills

Goal: increase useful autonomy without turning Work into a general-purpose
multi-agent platform.

- **Main Agent** owns the conversation, plan, approvals, Workspace write
  boundary, and final response. This is the user-visible agent in every Work
  thread; it is not a separately configured "Mate" role.
- **Subagents** are bounded workers created by the Main Agent for research,
  analysis, or other parallelizable subtasks. Work shows their task, status,
  elapsed time, result, and cancellation control. Subagents do not create a
  second user-facing conversation hierarchy.
- **Skills** are the primary extension mechanism. Work lists installed skills,
  explains compatibility or trust failures, and lets the user enable or
  disable them through the shared runtime state. Installation and updates must
  reuse the existing local, plugin, and ClawHub governance paths rather than a
  desktop-only package format.
- The Main Agent may delegate automatically when a task benefits from it, but
  all Workspace mutations pass through one writer and the existing approval,
  hook, sandbox, audit, and cancellation boundaries.
- Long-running work must survive the foreground turn lifecycle and surface a
  durable state instead of depending on an untracked background task.

Acceptance gate: a user can select Skills without editing configuration, see
why an unavailable Skill cannot run, observe and cancel a delegated Subagent,
and review one ordered set of file changes produced under the Main Agent's
authority. Restart and cancellation tests prove that no worker becomes an
orphan and no two workers concurrently write the same Workspace.

### 5. lightweight native architecture

Goal: Work ships only what the foreground desktop product needs.

- GPUI + Rust render every Work screen; no bundled React Web console;
- Server enables `embedded-web-ui` by default while Work explicitly disables
  it at the shared-runtime dependency boundary;
- Work has a dedicated `work-release` profile, bundle builder, and release
  artifacts;
- Server Web UI and channel adapters stay in the Server product;
- reusable lifecycle and storage code stays outside the GPUI crate;
- feature and crate boundaries should keep shrinking Work's transitive Server
  surface without introducing a second runtime.

Acceptance gate: release inspection proves the app bundle contains no `web/`
distribution, and size/dependency reports are recorded for each major release.

### 6. Linux and Windows portable previews

Goal: make ports observable and testable without overstating support.

Every release builds and publishes:

- `microclaw-work-<version>-x86_64-linux-gnu.tar.gz`;
- `microclaw-work-<version>-aarch64-linux-gnu.tar.gz`;
- `microclaw-work-<version>-x86_64-windows-msvc.zip`.

Each native runner compiles the real `microclaw-work` binary, launches it,
checks that it remains alive, packages the executable with its license and
Work README, and uploads the portable artifact. These are previews, not signed
installers. Formal Windows support still requires code signing, installer and
upgrade behavior, SmartScreen/Defender acceptance, accessibility, IME, high
DPI, and sustained-use evidence. Linux remains preview until a packaging and
desktop-integration target is selected from evidence.

## Sequence

1. Ship Work Skills discovery and enablement on the shared runtime boundary.
2. Make Main Agent delegation visible and controllable; enforce one Workspace
   writer and one approval path for all Subagent work.
3. Make delegated and long-running work durable across foreground turn and app
   lifecycle transitions.
4. Finish the macOS acceptance gates and daily-use feedback loop.
5. Deepen Workspace orientation and native desktop affordances.
6. Measure and reduce Work-only package/dependency weight.
7. Keep portable preview builds green and collect platform-specific defects.
8. Add optional pairing with a user-owned MicroClaw Server only after the
   standalone Work loop is dependable.

Named Agent teams, nested Subagent trees, a free-form multi-agent canvas,
native mobile, managed multi-tenant cloud, and a complete IDE remain outside
this plan.
