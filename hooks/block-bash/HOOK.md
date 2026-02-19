---
name: block-bash
description: Example hook that blocks bash tool execution
events: [BeforeToolCall]
command: "sh hook.sh"
enabled: false
timeout_ms: 1000
priority: 50
---

Example only. Disabled by default.
