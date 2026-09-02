---
id: work
title: MicroClaw Work
sidebar_position: 4
---

# MicroClaw Work

MicroClaw Work is the native, local-first desktop coworker built on the same
Rust Agent Engine as MicroClaw Server. It is designed for interactive project
work while you are at the computer: describe a task, follow the plan and tool
activity, approve sensitive actions, inspect changes, and continue or restore
the Workspace.

MicroClaw Server remains the deployable, always-on runtime for channels, Web,
APIs, schedules, background work, and remote automation. Work does not replace
Server, embed its React console, or implement a second Agent Loop.

## Platform status

| Product | macOS | Linux | Windows |
|---|---|---|---|
| MicroClaw Server | Supported | Supported | Supported |
| MicroClaw Work | Apple Silicon macOS 13+ supported | x86_64/ARM64 portable preview | x86_64 portable preview |

The Linux and Windows archives are early native GPUI builds. They pass a native
launch smoke test on every release, but they are not yet signed installers and
do not carry the same support commitment as the notarized macOS application.

## Install Work on macOS

```sh
brew tap microclaw/tap
brew install --cask microclaw-work
```

The Cask installs a Developer ID signed, Apple-notarized and stapled app. Work
uses a private local Work Home for the first conversation, so connecting a
project folder is optional during onboarding.

Portable preview archives are attached to each
[GitHub release](https://github.com/microclaw/microclaw/releases). Extract the
archive and run `microclaw-work` (`microclaw-work.exe` on Windows). Preview
users should expect platform-integration gaps and report them with the OS,
desktop environment, GPU, and launch logs.

## The local work loop

1. Configure a provider and model in native Settings, or use a detected Codex
   account without copying its token into Work configuration.
2. Keep the private Work Home or connect a project folder.
3. Start a durable conversation and describe the outcome you want. Attach up
   to eight files from the current Workspace with the native picker, or drag
   them onto the composer.
4. Inspect streamed plans, tool activity, process verification, subagents,
   approvals, file changes, and artifacts.
5. Approve a sensitive action once, allow it for the chat, or deny it.
6. Review the bounded multi-file diff and accept the result or restore the
   pre-task checkpoint.
7. Continue in the same conversation; drafts, task state, and runtime session
   survive relaunch.

Completed and failed runs post native in-app and operating-system
notifications. Approval pauses and deliberate cancellation stay quiet. On
macOS, Notification Center controls authorization and presentation for the
signed application bundle.

Artifacts are opened only after their canonical path resolves inside the
selected Workspace. Missing files, absolute escapes, and symlink escapes are
rejected. Work uses the shared tool risk, authorization, path, hook, and audit
boundaries rather than desktop-only bypasses.

The Workspace rail shows the connected project name, Git branch when
available, and the effective `current folder only` access scope. File
attachments follow the same rule: Work stores only Workspace-relative paths,
rejects external files, shows references in the durable conversation, and
asks the shared Agent Engine to inspect them through its governed filesystem
tools. File contents are not copied into the desktop session database.

## Native settings

Settings includes:

- Skills discovery, compatibility status, enable/disable controls, and one
  import field for local directories, GitHub references, or ClawHub slugs;

- provider presets, current model suggestions, custom model ID and compatible
  base URL;
- masked API-key replacement that never loads an existing secret into the UI;
- local `SOUL.md` content and path plus the shared project-context directory;
- system, light, and dark appearance (system is the default);
- active Workspace and Work Home controls, repository context, and the local
  access boundary;
- offline filesystem/configuration diagnostics and explicit provider and full
  first-response tests.

## Architecture

```text
GPUI desktop views
      |
microclaw-work-app       commands, projections, versioned session snapshots
      |
microclaw-work-runtime   foreground worker, cancellation, runtime event bridge
      |
shared MicroClaw Agent Engine, providers, tools, policy, memory, checkpoints
```

The Work runtime disables the root crate's `embedded-web-ui` feature, so its
binary and app bundle contain no React operator-console distribution. Model
calls, checkpoints, restore, and other blocking work run off the GPUI thread.
Server enables the feature by default and continues to own Web, channels,
schedules, remote delivery, and long-running automation.

See the [architecture guide](./architecture) for the complete Server/Work
boundary and the public [roadmap](./roadmap) for current acceptance gates.
