---
id: sdk-delegation
title: Main Agent delegation
description: Observe and control bounded Subagent work through the Rust SDK.
---

# Main Agent delegation

MicroClaw keeps one user-facing Main Agent. It can delegate bounded research,
analysis, and testing tasks to Subagents while retaining ownership of the
conversation, approvals, Workspace writes, and final response.

Subagent start and finish transitions appear in the parent run's ordered
`RuntimeEventEnvelope` stream. Durable state can also be projected after a UI
restart:

```rust
for task in microclaw.delegated_tasks("session-1", 100)? {
    println!("{}: {}", task.status.as_str(), task.task);
    if !task.status.is_terminal() {
        println!("progress: {:?}", task.progress);
    }
}
```

Cancel an active delegated task through the same persisted cancellation path
used by Work:

```rust
let accepted = microclaw.cancel_delegated_task("session-1", "subagent-run-id")?;
```

`true` means the cancellation request was recorded and signalled; the terminal
task state remains authoritative. Work Subagents are read-only at the Workspace
tool boundary, so the Main Agent remains the single writer and presents one
ordered change set for review.

This contract intentionally exposes one Main Agent with bounded delegated work,
not arbitrary peer-agent topology or recursive UI conversation trees.
