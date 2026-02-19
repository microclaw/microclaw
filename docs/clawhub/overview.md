# ClawHub Integration

## What it adds

MicroClaw integrates with ClawHub to search and install skill packs.

- CLI: `microclaw skill search|install|list|inspect|available`
- Agent tools: `clawhub_search`, `clawhub_install`
- Lockfile: `clawhub.lock.json` (managed install state)

## Storage locations

- Skills directory: `<data_dir>/skills` (default: `~/.microclaw/skills`)
- Lockfile: `<data_dir>/clawhub.lock.json` (default: `~/.microclaw/clawhub.lock.json`)
- Optional config override: `skills_dir` in `microclaw.config.yaml`

Compatibility behavior:
- Existing configured paths (`data_dir` / `skills_dir` / `working_dir`) are always respected.
- New defaults (`~/.microclaw`, `<data_dir>/skills`, `~/.microclaw/working_dir`) are used only when fields are not configured.

## Config

In `microclaw.config.yaml`:

```yaml
clawhub_registry: "https://clawhub.ai"
clawhub_token: ""
clawhub_agent_tools_enabled: true
clawhub_skip_security_warnings: false
```

## Operational notes

- Keep `clawhub_skip_security_warnings: false` in production.
- Review `clawhub.lock.json` in CI for supply-chain traceability.
- Pin versions in automation instead of implicit latest.
