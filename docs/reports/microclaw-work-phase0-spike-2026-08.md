# MicroClaw Work Phase 0 spike report

Status: **In progress** · Date: **2026-08-25**

This report records evidence from the first implementation increment of the
[`MicroClaw Work proposal`](../roadmap/microclaw-work-proposal-cn.md). It is a
technology spike, not a production desktop release.

## Implemented

- Added `apps/microclaw-work` as an independent workspace package.
- Added a native GPUI + GPUI Component application shell.
- Added Workspace, Task, Plan, Approval, Diff, and Artifact projections.
- Added an approval transition from `AwaitingApproval` to `Verifying`.
- Added a GPUI Component task input suitable for real IME validation.
- Added a timed synthetic Work event stream that moves from planning through
  tool activity to an approval pause.
- Added a framework-independent event projection capped at 200 entries.
- Kept lifecycle transitions in the framework-independent session domain; GPUI
  owns input, timers, rendering, and commands but not Work state policy.
- Added a versioned, framework-independent `WorkSessionSnapshot`.
- Added atomic snapshot persistence to the platform-local data directory and
  startup recovery.
- Pinned GPUI Component to `d5821f2` and the shared Zed/GPUI source to the
  component-tested `8b1497d` revision through `Cargo.lock`.
- Raised the workspace Rust baseline from 1.93.1 to 1.95.0, the minimum tested
  version that compiles the pinned GPUI revision.
- Added Linux, macOS, and Windows Work checks to Extended CI.
- Added a repeatable macOS `.app` bundler with versioned Info.plist validation,
  ad-hoc development signing, and strict signature verification.

## Verified on macOS arm64

```text
cargo check -p microclaw-work                 passed
cargo build -p microclaw-work                 passed
cargo test -p microclaw-work --lib            4 passed
cargo clippy -p microclaw-work --all-targets  passed with -D warnings
cargo check -p microclaw --lib                passed on Rust 1.95.0
scripts/build_work_macos_app.sh debug          passed; 73 MB app bundle
scripts/build_work_macos_app.sh release        passed; 13 MB app bundle
```

The binary entered its window event loop after both implementation increments
and remained running until it was terminated. The snapshot file was inspected
in the macOS Application Support directory. The development `.app` was also
launched successfully through macOS LaunchServices and its process was observed
before being stopped. Visual, task-input, and
accessibility inspection could not be completed during these runs because the
macOS session was locked.

## Important dependency finding

GPUI Component currently declares Zed dependencies from Git without a revision.
Pinning only the direct application dependency creates two incompatible GPUI
source identities. The workspace therefore uses one unqualified Git source and
pins its exact commit in `Cargo.lock`. Dependency upgrades must update GPUI and
GPUI Component as a tested pair and confirm that only one Zed commit is present
in the lockfile.

## Phase 0 work still open

- Inspect the running macOS UI visually and through the accessibility tree.
- Verify Chinese and English IME composition in a real input control.
- Exercise recovery by changing state, terminating the process, and relaunching.
- Run and fix the new CI matrix on Ubuntu, macOS, and Windows.
- Validate high-DPI, multi-monitor, sleep/wake, old GPU, and remote-desktop use.
- Add a real app icon and produce a DMG; Developer ID signing and notarization
  remain release work.

Phase 1 shared-runtime extraction should not start until the macOS/Windows
window, input, event-stream, and restart-recovery gates are demonstrated.
