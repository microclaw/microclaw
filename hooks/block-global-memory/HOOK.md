---
name: block-global-memory
description: Block global scope memory read/write to prevent cross-chat leakage
events: [BeforeToolCall]
command: "sh hook.sh"
enabled: true
timeout_ms: 1000
priority: 40
---

Policy hook: deny `read_memory` and `write_memory` when `tool_input.scope == "global"`.
