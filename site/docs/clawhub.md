---
id: clawhub
title: ClawHub
sidebar_position: 20
---

MicroClaw includes ClawHub skill-registry integration.

## Capabilities

- CLI: `microclaw skill search|install|list|inspect`
- Agent tools: `clawhub_search`, `clawhub_install`
- Managed lockfile for reproducible skill installs
- Local skills diagnostics: `microclaw skill available [--all]`

## Storage

- Skills: `<skills_dir>` (defaults to `<data_dir>/skills`, with `data_dir` default `~/.microclaw`)
- Lockfile: `<data_dir>/clawhub.lock.json` (default `~/.microclaw/clawhub.lock.json`)

Compatibility:
- Existing configured paths are preserved.
- Only when paths are not configured, new defaults apply.

## Configuration

```yaml
clawhub_registry: "https://clawhub.ai"
clawhub_token: ""
clawhub_agent_tools_enabled: true
clawhub_skip_security_warnings: false
```

## References

- Internal design note: `docs/clawhub/overview.md`
- Generated defaults: [Generated Config Defaults](./generated-config-defaults)
