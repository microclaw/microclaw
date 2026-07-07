# Security Audit Note — Web UI endpoint trust & ClawHub install boundary

Date: 2026-07-06 · Scope: two watch-items from
[`../roadmap/competitive-intel-update-2026-07.md`](../roadmap/competitive-intel-update-2026-07.md),
both derived from OpenClaw's 2026 H1 incidents.

## 1. Web UI: CVE-2026-25253-class endpoint trust — **not present**

OpenClaw's one-click RCE came from its Control UI trusting a `gatewayUrl` query
parameter and auto-connecting to it (leaking the gateway auth token cross-origin
over WebSocket). Audit of `web/src`:

- All API traffic goes through `web/src/lib/api.ts`, which fetches **relative
  paths only** with `credentials: 'same-origin'`. There is no code path that
  derives a fetch/WebSocket/EventSource base from a URL parameter.
- Query-string/hash inputs are limited to `?session=` (a session key echoed
  into same-origin API calls) and `#bootstrap` (a one-time token *for* the
  same-origin server, cleared from the hash after read in
  `clearBootstrapTokenFromHash`). Neither names an endpoint.
- The only absolute-URL configuration (LLM base URL, A2A peer base URLs) is
  server-side config edited through the authenticated settings API — not
  attacker-reachable via a crafted link.

No change required. Keep this invariant in review: **the web UI must never
connect to an endpoint named by URL parameters.**

## 2. ClawHub install: local scan boundary — **hardened**

The ClawHavoc campaign (341 malicious skills) and its follow-ups showed the
registry-side scanning can be bypassed (22 MB README padding past scanner size
caps, post-scan payload mutation). Previously `install_skill` relied entirely
on registry-provided VirusTotal flags. Now:

- **Bounded extraction into a staging dir** (fail closed): max 256 entries,
  8 MB per file, 32 MB total — enforced on the ACTUAL decompressed byte count
  while copying (`Read::take`), not on the zip metadata's declared sizes,
  which a crafted archive can understate. Entry paths are sanitized via
  `enclosed_name()` (zip-slip guard). An oversize-padded file rejects the
  whole install instead of being skipped by a scanner.
- **Post-extraction local injection scan** (on the staging dir): every text
  file (`md/txt/yaml/yml/json/toml`) is run through the shared
  `microclaw_core::injection_scan::scan_for_injection` (invisible-unicode,
  instruction-override, HTML/script, exfil command+URL patterns). Only after
  both checks pass is the staged tree swapped into the live skills dir — a
  rejected install can no longer damage a pre-existing hand-written skill at
  the same path. `skip_security` downgrades scan hits to warnings for
  operators who reviewed the skill by hand.
- `scan_for_injection` moved from `microclaw-storage` to `microclaw-core` so
  memory writes, agent-created skills (`skill_manage`), and ClawHub installs
  share one scanner; the storage path re-exports it (no caller changes).

Residual risk (accepted for now): runtime payload mutation — a skill whose
*declared* content is clean but whose helper script downloads instructions at
run time. Mitigation lives at the execution boundary (sandbox + egress control,
v0.4.0 Track B), not at install time.
