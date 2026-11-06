---
id: roadmap
title: Project Direction
sidebar_position: 15
---

# Project direction

MicroClaw develops around a small set of durable priorities instead of promising a fixed feature calendar.

## Current baseline

MicroClaw ships three products on one execution model. MicroClaw Server is the supported cross-platform, deployable Agent Runtime. MicroClaw Code (`mccode`, preview) is the terminal coding agent, with a themeable full-screen or inline TUI, layered settings with permission rules and hooks, editor integration over ACP, an MCP server and hand-off to a paired Server. `microclaw-sdk` embeds the same Agent Engine in other Rust applications.

## Active priorities

- Use MicroClaw Code 0.25 (themes, queue and steer, layered settings,
  permission rules, hooks, approvals in chat) with real models and fix what
  that finds; grow `mccode eval` with longer sessions and cases replayed from
  this repository's bug-fix history, so token use can be measured.
- Finish the 0.25 gaps: background a running command, rewind the
  conversation as well as the files, a sub-agent role model, and model prices
  for cost display.
- Reach more people: a VS Code integration over ACP and Windows on ARM
  builds.
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
