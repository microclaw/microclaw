# Plugin Smoke Test Example

This folder contains:

- `smoke-test.yaml`, a ready-to-use plugin for exercising:
- `context-test.yaml`, a plugin for validating prompt/document context injection

These examples exercise:

- Custom slash commands
- Plugin-defined agent tools
- Permission policies (`host_only`, `dual`, `sandbox_only`)
- Context providers (`kind: prompt` and `kind: document`)

## Install

1. Create your plugins directory (default):

```sh
mkdir -p ~/.microclaw/plugins
```

2. Copy one or both example manifests:

```sh
cp examples/plugins/smoke-test.yaml ~/.microclaw/plugins/
cp examples/plugins/context-test.yaml ~/.microclaw/plugins/
```

If you use a custom plugin directory, set it in `microclaw.config.yaml`:

```yaml
plugins:
  enabled: true
  dir: "/absolute/path/to/plugins"
```

## Slash command checks

Run in any chat/channel:

- `/plugin-ping`
- `/plugin-host`
- `/plugin-dual`
- `/plugin-sandbox`
- `/plugin-echo hello world`

## Admin checks (control chat only)

- `/plugins list`
- `/plugins validate`
- `/plugins reload`

## Tool checks (ask the agent)

- "Call `plugin_smoke_echo` with text `hello`"
- "Call `plugin_smoke_dual_time`"
- "Call `plugin_smoke_sandbox_id`"

## Context injection checks

After `context-test.yaml` is installed:

- `/plugin-context-help`
- Ask: `say hello`
- Expected: response begins with `[CTX_TEST_OK] `
- Ask: `what context doc token do you see?`
- Expected: response mentions `CTX-DOC:web` (and may include chat/query details)
