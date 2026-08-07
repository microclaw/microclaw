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
clawhub_verify_on_load: block
```

## Load-time integrity verification

Installs record a `treeHash` fingerprint of the extracted skill tree in the
lockfile. `clawhub_verify_on_load` controls what happens when skills load
(startup and `/reload-skills`) and the tree on disk no longer matches:

- `block` (default): the skill becomes unavailable — excluded from the agent
  catalog, `activate_skill` fails with an actionable message, and the skill is
  listed under "Unavailable skills" with the reason in the CLI and web UI.
  Reinstall to restore integrity.
- `warn`: mismatches are only logged.
- `off`: no load-time check.

Entries installed before tree hashing existed (no recorded hash) log a warning
and stay available regardless of mode — reinstall once to pin them. On-demand
verification stays available via `microclaw skill verify`.

This closes the post-install-mutation window: a payload that rewrites an
installed skill after the install-time scan no longer reaches the agent.

## Operational notes

- Keep `clawhub_skip_security_warnings: false` in production.
- Keep `clawhub_verify_on_load: block` in production.
- Review `clawhub.lock.json` in CI for supply-chain traceability.
- Pin versions in automation instead of implicit latest.
