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
```

## Notes

- Custom slash commands are matched by first token (for example `/announce hello`).
- Plugin tools are registered at startup and available to the agent loop.
- Existing plugin tool behavior is hot-reloaded at execution time. Adding brand new tool names still requires restart.
- `execution_policy` supports:
  - `host_only`
  - `sandbox_only`
  - `dual` (sandbox when enabled, otherwise host)
- `permissions.allowed_channels` can restrict by runtime channel name.
- `permissions.require_control_chat: true` requires chat ID to be in `control_chat_ids`.
- Templates are strict: missing `{{var}}` placeholders fail with a clear error.
- Control chats can use `/plugins list`, `/plugins validate`, and `/plugins reload`.
