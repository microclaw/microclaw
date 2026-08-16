---
id: roadmap
title: Project Direction
sidebar_position: 15
---

# Project direction

MicroClaw develops around a small set of durable priorities instead of promising a fixed feature calendar.

## Current baseline

Version **v0.5.0** ships the channel-independent runtime, resumable execution, durable delivery, Web operator console, skills and plugins, MCP/ACP/A2A integration, scheduling, memory, hooks, governance, and observability. The release also decomposes the largest runtime and Web modules so future changes remain reviewable.

## Active priorities

- Make long-running work easier to inspect, resume, cancel, and recover safely.
- Keep tool execution and extensions behind shared authorization, sandbox, egress, and audit boundaries.
- Continue decomposing broad storage and runtime modules along stable domain boundaries.
- Reduce release and contributor build latency without weakening the verification matrix.
- Improve cross-channel progress delivery while keeping agent behavior channel-independent.
- Retire dependency advisory exceptions as upstream fixes become available.

## Design constraints

MicroClaw does not pursue channel count for its own sake, require a vector database as a core dependency, or allow extensions to bypass runtime governance. New work should strengthen the shared runtime rather than introduce channel-specific agent loops.

For dated planning material and implementation status, see the repository's [`docs/roadmap/`](https://github.com/microclaw/microclaw/tree/main/docs/roadmap) directory. Shipped behavior is documented in the main guides and [release notes](https://github.com/microclaw/microclaw/releases).
