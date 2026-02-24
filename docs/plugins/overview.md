# Plugin support (initial)

Plugin manifests are loaded from `<data_dir>/plugins` by default.
You can override the directory in config:

```yaml
plugins:
  enabled: true
  dir: "./microclaw.data/plugins"
```

## Example plugin manifest

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

## Notes

- Custom slash commands are matched by first token (for example `/announce hello`).
- Plugin tools are registered at startup and available to the agent loop.
- Plugin tool names and behavior are loaded dynamically on each turn (no restart required).
- `execution_policy` supports:
  - `host_only`
  - `sandbox_only`
  - `dual` (sandbox when enabled, otherwise host)
- `permissions.allowed_channels` can restrict by runtime channel name.
- `permissions.require_control_chat: true` requires chat ID to be in `control_chat_ids`.
- Templates are strict: missing `{{var}}` placeholders fail with a clear error.
- Control chats can use `/plugins list`, `/plugins validate`, and `/plugins reload`.
- Context providers can inject extra system context every turn:
  - `kind: prompt` for behavioral/policy instructions
  - `kind: document` for reference docs/spec fragments
  - Exactly one of `content` or `run` must be set.
  - Template variables: `{{channel}}`, `{{chat_id}}`, `{{query}}`, `{{plugin}}`, `{{provider}}`
  - `permissions.allowed_channels` and `permissions.require_control_chat` apply here too.
  - `permissions.execution_policy` can force `sandbox_only` for provider `run` commands.
