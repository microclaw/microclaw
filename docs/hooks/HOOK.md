# HOOK.md Specification

Each hook lives under:

```
hooks/<hook-name>/HOOK.md
hooks/<hook-name>/<script files>
```

`HOOK.md` must start with YAML frontmatter:

```md
---
name: block-bash
description: Block bash tool usage
events: [BeforeToolCall, AfterToolCall]
command: "sh hook.sh"
enabled: true
timeout_ms: 1500
priority: 100
---

Free-form notes for maintainers.
```

## Fields

- `name` (optional): hook id. Defaults to folder name.
- `description` (optional): human-readable summary.
- `events` (required): supported values:
  - `BeforeLLMCall`
  - `BeforeToolCall`
  - `AfterToolCall`
- `command` (required): shell command executed in hook folder.
- `enabled` (optional, default `true`): default enable state.
- `timeout_ms` (optional, default `1500`): execution timeout.
- `priority` (optional, default `100`): lower runs first.

## Hook I/O Contract

Hook runtime writes one JSON object to stdin:

- `BeforeLLMCall`: includes `system_prompt`, `iteration`, message/tool counts.
- `BeforeToolCall`: includes `tool_name` and `tool_input`.
- `AfterToolCall`: includes `tool_name`, `tool_input`, and tool `result`.

Hook command must print JSON to stdout:

```json
{"action":"allow"}
```

```json
{"action":"block","reason":"policy blocked"}
```

```json
{"action":"modify","patch":{"system_prompt":"..."}}
```

## Modify Patch Fields

- `BeforeLLMCall`:
  - `system_prompt` (string)
- `BeforeToolCall`:
  - `tool_input` (object)
- `AfterToolCall`:
  - `content` (string)
  - `is_error` (bool)
  - `error_type` (string)
  - `status_code` (number)

## CLI

- `microclaw hooks list`
- `microclaw hooks info <name>`
- `microclaw hooks enable <name>`
- `microclaw hooks disable <name>`

Enable/disable state is persisted in:

`<runtime>/hooks_state.json`

## Runtime Switches

Optional channel config:

```yaml
channels:
  hooks:
    enabled: true
    max_input_bytes: 131072
    max_output_bytes: 65536
```
