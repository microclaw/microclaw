---
slug: /subagents
title: "Subagents in MicroClaw: Background Work Without Blocking Chat"
authors: [microclaw]
tags: [agents, runtime, architecture]
---

The old way to delegate work inside an agent was to nest another mini-agent loop inside one tool call.

MicroClaw is moving past that shape with session-native subagents: asynchronous runs with IDs, lifecycle state, limits, and follow-up controls.

<!-- truncate -->

## What changed

Instead of treating delegation like an opaque internal trick, MicroClaw exposes a real subagent runtime:

- `sessions_spawn` starts a run and returns immediately
- `subagents_list` and `subagents_info` show state
- `subagents_kill` cancels active work
- `subagents_focus`, `subagents_focused`, and `subagents_send` turn one run into an ongoing work lane
- `subagents_log` exposes timeline events
- `subagents_retry_announces` flushes pending completion notices for control chats

That makes subagents something operators can reason about, not just something hidden inside one model turn.

## Why asynchronous runs matter

In a chat interface, blocking the parent conversation is expensive.

If a delegated task needs several tool iterations, large repo scans, or slower model passes, the main chat should stay responsive. Session-native subagents do exactly that:

1. parent agent spawns background work
2. run enters `accepted -> queued -> running`
3. parent chat can continue handling other messages
4. completion lands as `completed`, `failed`, `timed_out`, or `cancelled`

This is a better operational model for real tasks than hiding all delegation inside a single synchronous tool call.

## Safety boundaries

Subagents are not full-power clones of the main agent.

MicroClaw applies several guardrails:

- restricted child registry through `ToolRegistry::new_sub_agent`
- per-chat active-run limits
- per-parent child-run limits
- configurable timeout with `subagents.run_timeout_secs`
- bounded nesting with `subagents.max_spawn_depth`

By default, max spawn depth is conservative. You can open it up deliberately when you want orchestration instead of accidental recursion.

## Practical workflow

A typical pattern looks like this:

```text
1. Spawn a worker with sessions_spawn
2. Keep chatting in the parent session
3. Inspect progress with subagents_list or subagents_info
4. Focus the chat on one run if follow-up work should stay attached
5. Send continuation work with subagents_send
```

That focus/send model matters because it turns subagents from one-off helpers into durable task lanes inside a normal chat surface.

## Where this helps

### Repo work

Spawn a background code scan, let it collect findings, then ask follow-up questions against the focused run.

### Ops and incidents

Keep the main room responsive while one worker investigates logs, another summarizes alerts, and another drafts a status update.

### Structured orchestration

For bounded fan-out work, MicroClaw also includes `subagents_orchestrate`, which builds on the same runtime instead of inventing a separate execution path.

## The architectural point

This is not just "multi-agent" branding.

The meaningful change is that delegation now has durable state in the runtime and database: run IDs, status transitions, budgets, cancellation, result text, and event logs. That gives MicroClaw a cleaner foundation for observability, retries, and future orchestration patterns.

## Read next

- [Tools reference](/docs/tools)
- [Context lifecycle](/docs/architecture-context)
- [Roadmap](/docs/roadmap)
