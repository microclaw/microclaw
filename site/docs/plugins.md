---
id: plugins
title: Plugins
sidebar_position: 8
---

MicroClaw supports manifest-based plugins for slash commands, dynamic tools, and context providers.

## Directory and config

By default, plugin manifests are loaded from:

`<data_dir>/plugins`

You can override this in `microclaw.config.yaml`:

```yaml
plugins:
  enabled: true
  dir: "./microclaw.data/plugins"
```

## Example manifest

```yaml
name: ops
enabled: true

commands:
  - command: /uptime
    description: Show host uptime
    run:
      command: "uptime"
      timeout_secs: 10
      execution_policy: host_only

  - command: /safe-ls
    description: List current chat working directory in sandbox
    run:
      command: "ls -la"
      timeout_secs: 10
      execution_policy: sandbox_only

  - command: /announce
    description: Echo command args
    response: "Announcement: {{args}}"

tools:
  - name: plugin_safe_ls
    description: List files in the plugin working directory
    input_schema:
      type: object
      properties: {}
      required: []
    permissions:
      execution_policy: sandbox_only
      allowed_channels: ["telegram", "discord", "web"]
    run:
      command: "ls -la"
      timeout_secs: 10

context_providers:
  - name: policy_prompt
    kind: prompt
    content: "Always include a short risk summary for shell actions in channel {{channel}}."

  - name: runbook_doc
    kind: document
    permissions:
      execution_policy: host_only
    run:
      command: "cat ./docs/operations/runbook.md"
      timeout_secs: 10
```

## Behavior notes

- Slash commands are matched by first token (for example `/announce hello`).
- Plugin tool names and behavior are loaded dynamically on each turn (no restart required).
- `execution_policy` supports `host_only`, `sandbox_only`, and `dual`.
- `permissions.allowed_channels` restricts plugin execution by runtime channel.
- `permissions.require_control_chat: true` requires chat ID to be in `control_chat_ids`.
- Templates are strict: missing placeholders fail with a clear error.

Control-chat plugin admin commands:

- `/plugins list`
- `/plugins validate`
- `/plugins reload`

Context provider notes:

- `kind: prompt` for behavioral/policy instructions
- `kind: document` for reference docs/spec fragments
- Exactly one of `content` or `run` must be set
- Template variables: `{{channel}}`, `{{chat_id}}`, `{{query}}`, `{{plugin}}`, `{{provider}}`

