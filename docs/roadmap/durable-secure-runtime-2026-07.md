# Durable Coworker and Secure Runtime — Delivery Record

Status: **complete; draft PR ready for review**
Date: 2026-07-27

This is the authoritative status document for the Durable Coworker and Secure
Runtime milestones. Earlier roadmap files are historical planning records and
link here where their planned items have been superseded.

## Scope

### Milestone 1: Durable Coworker

Delivered in the current change:

- durable, provider-neutral interactive-turn checkpoints in SQLite;
- safe-boundary resume after restart;
- explicit non-resumable state while tools may be producing side effects;
- tool/result pairing validation before recovery;
- preservation of the last safe checkpoint if recovery itself crashes;
- stale-run retirement and orphaned subagent cleanup;
- recovery evidence and tamper-evident audit events;
- `/status` and Web Governance visibility;
- reuse of the existing durable outbound delivery ledger.

The runtime does **not** promise exactly-once execution for arbitrary external
tools. A crash during tool execution stops for reconciliation and never
blindly replays the call.

### Milestone 2: Secure Runtime

Delivered in the current change:

- per-chat, per-channel, and per-principal tool capability grants;
- principals for main, scheduler, direct channel, and subagent execution;
- global policy remains authoritative over scoped grants;
- centralized HTTP(S) destination policy for configured endpoints and shared
  tool inputs;
- private/metadata address checks plus exact/wildcard host lists;
- audit events for grant and egress decisions;
- sandbox credential filtering and exact-name escape hatch;
- no wholesale dotenv forwarding to containers;
- doctor/config self-check and Web Governance controls.

Arbitrary commands can construct destinations dynamically or use non-HTTP
protocols. Strong command egress therefore requires the existing
`sandbox.no_network: true` container boundary; the input-level egress policy is
not described as OS-level packet filtering.

### Milestone 3 research: TypeScript plugins

RFC 0006 defines the researched direction:

- TypeScript authoring through a versioned SDK;
- deterministic locked build and immutable bundle;
- supervised out-of-process stdio JSON-RPC host;
- per-plugin principal and default-deny capabilities;
- Rust-mediated filesystem, fetch, secret, and tool APIs;
- container/OS isolation as the security boundary;
- Node first for ecosystem compatibility, Deno as a possible adapter;
- no WASM architecture.

TypeScript runtime implementation is intentionally not part of the first two
milestones.

## Evidence matrix

| Requirement | Authoritative implementation | Verification |
|---|---|---|
| Safe checkpoint persistence | `active_turns` schema v31 and `checkpoint_active_turn` | storage migration/lifecycle tests |
| Resume without checkpoint loss | `mark_turn_recovery_started`, startup recovery keeps row until terminal | recovery-restart boundary test |
| Never replay uncertain tool | `executing_tools` writes `resumable=false` with tool summary | storage + recovery validator tests |
| Provider-neutral session validity | full tool-use/result pairing validator | valid/dangling checkpoint tests |
| Operator evidence | `/status`, `/api/governance`, `turn_recovery` audit | Rust/web build and API tests |
| Scoped capabilities | `evaluate_tool_policy_for_auth` at shared registry | policy unit and permission tests |
| Central egress | `microclaw-tools::egress`, config load, shared registry | URL/host/private/config tests |
| Credential boundary | sandbox host-side dotenv parsing/filtering | sandbox environment tests |
| Config operability | setup output, example config, doctor, Web Governance | config tests, web build, generated docs |
| TypeScript direction | RFC 0006 with official runtime/protocol references | documentation review |

## Required completion gates

This record must not be changed to **complete** until all are true:

- [x] focused recovery, egress, grant, sandbox, and permission tests pass;
- [x] `cargo check --workspace --all-targets --all-features` passes;
- [x] `cargo test` passes (1118 passed, 5 ignored);
- [x] `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes;
- [x] `npm --prefix web run build` passes;
- [x] generated documentation check passes;
- [x] linked GitHub issue:
  [#463](https://github.com/microclaw/microclaw/issues/463);
- [x] draft pull request:
  [#464](https://github.com/microclaw/microclaw/pull/464);
- [x] all 10 GitHub Actions checks are green on draft PR #464, including
  cross-platform Rust, Web/Docs, Docker, Nix, coverage, security, stability,
  and release-build gates.

`cargo fmt --all -- --check` was also run. It reports repository-wide
formatting drift in untouched files that exists independently of this change.
The unrelated 50-file formatting rewrite was removed from this branch; GitHub
does not currently define rustfmt as a required check. This baseline should be
fixed in a dedicated formatting-only change rather than hidden inside a
runtime/security review.

GitHub delivery is tracked in
[Issue #463](https://github.com/microclaw/microclaw/issues/463) and
[draft PR #464](https://github.com/microclaw/microclaw/pull/464). Record the
final required-check result here rather than creating another status document.
The first complete remote validation finished successfully on 2026-07-27:
[CI](https://github.com/microclaw/microclaw/actions/runs/30233151784) and
[Extended CI](https://github.com/microclaw/microclaw/actions/runs/30233151758).
