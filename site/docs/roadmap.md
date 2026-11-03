---
id: roadmap
title: Project Direction
sidebar_position: 15
---

# Project direction

MicroClaw develops around a small set of durable priorities instead of promising a fixed feature calendar.

## Current baseline

MicroClaw ships three products on one execution model. MicroClaw Server is the supported cross-platform, deployable Agent Runtime. MicroClaw Code (`mccode`, preview) is the terminal coding agent. `microclaw-sdk` embeds the same Agent Engine in other Rust applications. MicroClaw Work, the earlier desktop app, has been discontinued; Server keeps its revocable device pairing for local clients.

## Active priorities

- Make MicroClaw Code a dependable daily coding tool: in-engine approvals,
  one tool-policy evaluator, an OS-level sandbox and command-prefix allow
  rules, then session tooling (fork, undo, review) and editor integration.
- Measure Code on a coding evaluation set before adding heavier machinery
  such as LSP diagnostics or a repository index.
- Keep Server and Code on one provider-neutral Agent Engine, with Code
  reaching it only through `microclaw-sdk`.
- Preserve Server support, channels, APIs, scheduling, Web management,
  security boundaries, and recovery on macOS, Linux, and Windows.

## Design constraints

MicroClaw does not pursue channel count for its own sake, require a vector database as a core dependency, or allow extensions to bypass runtime governance. New work should strengthen the shared runtime rather than introduce channel-specific agent loops.

The canonical dated plan is
[`work-server-local-first-plan-2026-08.md`](https://github.com/microclaw/microclaw/blob/main/docs/roadmap/work-server-local-first-plan-2026-08.md).
Shipped behavior is documented in the [MicroClaw Code guide](./code), main guides, and
[release notes](https://github.com/microclaw/microclaw/releases).
