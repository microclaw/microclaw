---
id: roadmap
title: Project Direction
sidebar_position: 15
---

# Project direction

MicroClaw develops around a small set of durable priorities instead of promising a fixed feature calendar.

## Current baseline

MicroClaw ships three products on one execution model. MicroClaw Server is the supported cross-platform, deployable Agent Runtime. MicroClaw Code (`mccode`, preview) is the terminal coding agent, with a full-screen TUI, editor integration over ACP, an MCP server and hand-off to a paired Server. `microclaw-sdk` embeds the same Agent Engine in other Rust applications.

## Active priorities

- Ship MicroClaw Code as a release (its own `mccode` archives and Homebrew
  formula) and measure it with `mccode eval` on real coding tasks, including
  cases replayed from this repository's bug-fix history.
- Let evaluation results decide the next investments: a real pseudo-terminal
  for TTY-only programs, seccomp on top of the OS sandbox, syncing the local
  repository for remote runs, or heavier machinery such as LSP diagnostics.
- Keep Server and Code on one provider-neutral Agent Engine, with Code
  reaching it only through `microclaw-sdk`.
- Preserve Server support, channels, APIs, scheduling, Web management,
  security boundaries, and recovery on macOS, Linux, and Windows.

## Design constraints

MicroClaw does not pursue channel count for its own sake, require a vector database as a core dependency, or allow extensions to bypass runtime governance. New work should strengthen the shared runtime rather than introduce channel-specific agent loops.

The canonical plan is the
[MicroClaw Code proposal](https://github.com/microclaw/microclaw/blob/main/docs/roadmap/microclaw-code-proposal-cn.md).
Shipped behavior is documented in the [MicroClaw Code guide](./code), main guides, and
[release notes](https://github.com/microclaw/microclaw/releases).
