---
name: filter-global-structured-memory
description: Remove global rows from structured_memory_search output
events: [AfterToolCall]
command: "sh hook.sh"
enabled: true
timeout_ms: 1000
priority: 70
---

Policy hook: for `structured_memory_search`, strip lines containing `[global]`.
