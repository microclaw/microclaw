# Execution Model (Current)

## Default posture

- `sandbox.mode` remains `off` by default to keep first-run setup friction low.
- High-risk actions are guarded by tool risk + approval gates.
- File tools are protected by path guards, sensitive-path blocking, symlink validation, and optional external allowlists.

## Sandbox posture

- Runtime: Docker backend (`auto` / `docker`).
- Enable quickly: `microclaw setup --enable-sandbox`.
- Verify readiness: `microclaw doctor sandbox`.
- If sandbox is enabled but runtime is unavailable:
  - `require_runtime = true`: fail closed.
  - `require_runtime = false`: warn and fall back to host execution.

## Tool execution policy tags

- `bash`: `dual`
- `write_file`: `host-only`
- `edit_file`: `host-only`
- all others: `host-only` (current baseline)

Policy metadata is enforced before tool execution and surfaced in web config self-check.

## Mount and path controls

- Sandbox mount validation:
  - sensitive component blocklist (`.ssh`, `.aws`, `.gnupg`, `.kube`, `.docker`, `.env`, keys, etc.)
  - symlink component rejection
  - optional external mount allowlist (`~/.config/microclaw/mount-allowlist.txt`)
- File path guard:
  - sensitive path deny list
  - symlink validation on existing path prefix
  - optional external path allowlist (`~/.config/microclaw/path-allowlist.txt`)

## Web Fetch Controls

`web_fetch` applies defense-in-depth controls before tool output reaches the agent:

- URL policy validation:
  - allowed schemes (`web_fetch_url_validation.allowed_schemes`)
  - explicit host denylist/allowlist
  - optional remote feed sync that augments host allowlist/denylist
- Content validation:
  - regex-based prompt-injection and tool-abuse pattern detection on fetched text
  - strict mode blocks on any matched pattern; non-strict mode blocks high-confidence or multi-pattern hits

Order of enforcement:

1. URL policy check (before outbound request)
2. fetch and HTML-to-text extraction
3. content validation check (before returning tool result)

For production environments, use:

- explicit host denylist entries for local/metadata endpoints
- narrow allowlist for known domains where feasible
- feed sync with `fail_open: false` when you prefer fail-closed behavior during feed outages

## Operational recommendation

- Keep default `sandbox=off` for onboarding.
- For production or higher-risk deployments, enable sandbox and require an explicit allowlist.
