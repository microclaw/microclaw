---
id: desktop
title: MicroClaw Desktop
sidebar_position: 4
---

# MicroClaw Desktop

MicroClaw Desktop is the native, local-first desktop coworker built on the same
Rust Agent Engine as MicroClaw Server. It is designed for interactive project
work while you are at the computer: describe a task, follow the plan and tool
activity, approve sensitive actions, inspect changes, and continue or restore
the Workspace.

MicroClaw Server remains the deployable, always-on runtime for channels, Web,
APIs, schedules, background work, and remote automation. Desktop does not replace
Server, embed its React console, or implement a second Agent Loop.

## Platform status

| Product | macOS | Linux | Windows |
|---|---|---|---|
| MicroClaw Server | Supported | Supported | Supported |
| MicroClaw Desktop | Apple Silicon macOS 13+ supported | x86_64/ARM64 portable preview | x86_64 portable preview |

The Linux and Windows archives are early native GPUI builds. They pass a native
launch smoke test on every release, but they are not yet signed installers and
do not carry the same support commitment as the notarized macOS application.

## Install Desktop on macOS

```sh
brew tap microclaw/tap
brew install --cask microclaw-desktop
```

The Cask installs a Developer ID signed, Apple-notarized and stapled app. Desktop
uses a private local Desktop Home for the first conversation, so connecting a
project folder is optional during onboarding.

Portable preview archives are attached to each
[GitHub release](https://github.com/microclaw/microclaw/releases). Extract the
archive and run `microclaw-desktop` (`microclaw-desktop.exe` on Windows). Preview
users should expect platform-integration gaps and report them with the OS,
desktop environment, GPU, and launch logs.

## The local work loop

1. Configure a provider and model in native Settings, or use a detected Codex
   account without copying its token into Desktop configuration.
2. Keep the private Desktop Home or connect a project folder.
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
rejected. Desktop uses the shared tool risk, authorization, path, hook, and audit
boundaries rather than desktop-only bypasses.

The Workspace rail shows the connected project name, Git branch when
available, and the effective `current folder only` access scope. File
attachments follow the same rule: Desktop stores only Workspace-relative paths,
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
- active Workspace and Desktop Home controls, repository context, and the local
  access boundary;
- offline filesystem/configuration diagnostics and explicit provider and full
  first-response tests.

## Connect Desktop to a MicroClaw Server

Desktop can submit tasks to a MicroClaw Server you run instead of the embedded
engine on this computer. Pairing is explicit and revocable:

1. In the Server's Web console open **Settings → Access → Paired devices** and
   click **Create pairing code**. The code is eight characters, single-use,
   and expires after the chosen number of minutes (10 by default).
2. In Desktop open **Settings → Server**, enter the Server URL
   (for example `https://claw.example.com`) and the code, then click **Pair**.
   Desktop stores the issued device token in `remote-server.json` under its data
   directory with owner-only permissions. The token carries
   `operator.read` and `operator.write` only; it cannot change Server
   configuration or manage credentials.
3. Switch the execution target to **Server**. The composer chip changes from
   `Local` to `Server · <device label>` so it is always visible where a task
   runs. Progress, tool activity, approvals, and Stop work the same way as
   locally; the Server owns the working directory and permission scope for
   those runs.

To disconnect, click **Unpair** in Desktop (removes the local token) or
**Revoke** in the Server console (the device's next request is rejected and
Desktop shows that it has to pair again). From a terminal,
`microclaw-desktop-headless pair <server_url> <code>` pairs without the desktop
UI and `microclaw-desktop-headless server "<task>"` runs one task against the
paired Server.

## Architecture

```text
GPUI desktop views
      |
microclaw-desktop-app       commands, projections, versioned session snapshots
      |
microclaw-desktop-runtime   foreground worker, cancellation, runtime event bridge
      |
microclaw-sdk
      |
shared MicroClaw Agent Engine, providers, tools, policy, memory, checkpoints
```

Desktop depends on the SDK's `full` Engine facade rather than the root Server
package, so its binary and app bundle contain no React operator-console
distribution or concrete channel adapters. Model calls, checkpoints, restore,
and other blocking work run off the GPUI thread. Server continues to own Web,
channels, schedules, remote delivery, and long-running automation.

See the [architecture guide](./architecture) for the complete Server/Desktop
boundary and the public [roadmap](./roadmap) for current acceptance gates.
