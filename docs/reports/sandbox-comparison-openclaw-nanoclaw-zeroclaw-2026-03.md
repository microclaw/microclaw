# Sandbox Capability Comparison (OpenClaw / NanoClaw / ZeroClaw)

Date: 2026-03-05

## Sources

- OpenClaw README sandbox section: https://github.com/openclaw/openclaw/blob/main/README.md
- NanoClaw README and security model:
  - https://github.com/qwibitai/nanoclaw/blob/main/README.md
  - https://github.com/qwibitai/nanoclaw/blob/main/docs/SECURITY.md
- ZeroClaw runtime + sandbox docs:
  - https://github.com/zeroclaw-labs/zeroclaw/blob/dev/README.md
  - https://github.com/zeroclaw-labs/zeroclaw/blob/dev/docs/config-reference.md
  - https://github.com/zeroclaw-labs/zeroclaw/blob/dev/docs/frictionless-security.md

## High-level comparison

| Project | Sandbox posture | Runtime options | Fallback posture | Notable strengths |
|---|---|---|---|---|
| OpenClaw | Optional Docker sandbox, session/tool policy layering | Docker-centric | Can run host-side depending mode/policy | Mature policy model and channel/session routing depth |
| NanoClaw | Container-first execution model | Docker by default, Apple Container option | Designed around container isolation by default | Strong isolation narrative, explicit mount discipline |
| ZeroClaw | Secure-by-default framing with multi-runtime direction | Native + containerized pathways (docs include multiple backends) | Runtime-dependent, layered controls | Broad runtime abstraction and strict config contract docs |
| MicroClaw (before this PR) | Docker-only container runtime wiring | `auto`/`docker` | configurable fail-open/fail-closed | Strong path guards + approval gates |

## Gap analysis for MicroClaw

1. Container runtime portability:
MicroClaw sandbox runtime detection and health checks were Docker-specific, which creates friction on setups that standardize on Podman.

2. Diagnostics language and API surface:
`doctor sandbox` and `/api/config/self_check` used Docker-specific messaging, reducing clarity when backend is `auto` and users run non-Docker engines.

3. Fail-closed ergonomics:
This branch already changes `require_runtime` default to `true`, aligning behavior with strict sandbox expectations.

## Enhancements included in this PR

1. Added Podman support in sandbox runtime resolution:
- `SandboxBackend` now supports `podman`.
- Podman is used only when explicitly configured (`backend: podman`).
- `auto` remains Docker-first and Docker-only for backward compatibility.

2. Unified runtime checks:
- Added backend-aware runtime selection/availability helpers in `microclaw-tools::sandbox`.
- `SandboxRouter` now uses backend-aware runtime resolution instead of Docker-only probing.

3. Updated fail/diagnostic messaging:
- Runtime-unavailable error/warn text now references generic "container runtime".
- `doctor sandbox` now checks backend-aware CLI/runtime availability (`docker`/`podman`).
- Web self-check now reports backend-aware runtime availability and selected runtime CLI.

4. Updated docs and operator hint text:
- Security model doc updated from Docker-only language to container runtime language.
- Setup tip text updated to "container runtime" wording.

## Follow-up optimization candidates (not in this PR)

1. Runtime priority config for `auto`:
Allow explicit priority ordering (`podman,docker`) to match enterprise host standards.

2. Sandbox readiness cache:
Cache runtime capability/version probe results for a short TTL to reduce repeated `info` calls.

3. Granular fallback policy:
Support policy modes beyond boolean `require_runtime` (for example: `fail`, `warn_once`, `warn_every_turn`).

4. Rootfs write policy hardening:
Evaluate read-only root mount with explicit writable submounts for tighter parity with NanoClaw’s isolation stance.
