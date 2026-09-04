---
id: roadmap
title: Project Direction
sidebar_position: 15
---

# Project direction

MicroClaw develops around a small set of durable priorities instead of promising a fixed feature calendar.

## Current baseline

Version **v0.6.0** defines two product surfaces on one execution model. MicroClaw Server is the supported cross-platform, deployable Agent Runtime. MicroClaw Work is the local-first native GPUI desktop coworker, formally supported on Apple Silicon macOS with Linux and Windows portable previews published on every release.

## Active priorities

- Finish the macOS Work acceptance gates: clean-account install, first task,
  update/uninstall, VoiceOver, completion notification, and sustained daily use.
- Deepen the local Workspace loop with repository orientation, clear permission
  scope, native attachments and background task visibility.
- Keep Work and Server on one provider-neutral Agent Engine and reduce Work's
  transitive Server surface without embedding the Web console.
- Keep Linux x86_64/ARM64 and Windows x86_64 portable Work previews building,
  launching, and publishing automatically without presenting them as signed
  production installers.
- Preserve Server support, channels, APIs, scheduling, Web management,
  security boundaries, and recovery on macOS, Linux, and Windows.

## Design constraints

MicroClaw does not pursue channel count for its own sake, require a vector database as a core dependency, or allow extensions to bypass runtime governance. New work should strengthen the shared runtime rather than introduce channel-specific agent loops.

The canonical dated plan is
[`work-server-local-first-plan-2026-08.md`](https://github.com/microclaw/microclaw/blob/main/docs/roadmap/work-server-local-first-plan-2026-08.md).
Shipped behavior is documented in the [Work guide](./work), main guides, and
[release notes](https://github.com/microclaw/microclaw/releases).
