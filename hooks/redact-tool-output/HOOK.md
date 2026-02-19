---
name: redact-tool-output
description: Example hook that redacts long tool output
events: [AfterToolCall]
command: "sh hook.sh"
enabled: false
timeout_ms: 1000
priority: 80
---

Example only. Disabled by default.
