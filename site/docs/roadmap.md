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

- Test MicroClaw Code against real models and fix what that finds before
  adding features; grow `mccode eval` with longer sessions and cases replayed
  from this repository's bug-fix history, so token use can be measured.
- Reach more people: model presets for popular coding models (window, output
  limit, image support, price), a VS Code integration over ACP, and Windows
  on ARM builds.
- Close the Windows gap: an OS sandbox for shell commands on Windows
  (today Windows asks before every command).
- Keep Server and Code on one provider-neutral Agent Engine, with Code
  reaching it only through `microclaw-sdk`.
- Preserve Server support, channels, APIs, scheduling, Web management,
  security boundaries, and recovery on macOS, Linux, and Windows.

## Design constraints

MicroClaw does not pursue channel count for its own sake, require a vector database as a core dependency, or allow extensions to bypass runtime governance. New work should strengthen the shared runtime rather than introduce channel-specific agent loops.

The current plan is
[next-plan-2026-11-cn.md](https://github.com/microclaw/microclaw/blob/main/docs/roadmap/next-plan-2026-11-cn.md);
the [MicroClaw Code proposal](https://github.com/microclaw/microclaw/blob/main/docs/roadmap/microclaw-code-proposal-cn.md)
explains the product line.
Shipped behavior is documented in the [MicroClaw Code guide](./code), main guides, and
[release notes](https://github.com/microclaw/microclaw/releases).
