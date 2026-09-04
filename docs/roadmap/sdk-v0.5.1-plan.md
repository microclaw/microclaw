# Rust SDK v0.5.1 execution plan

Status: **Delivered**  
Opened: 2026-09-04  
Delivered: 2026-09-04  
Release type: patch, compatible with the 0.5 public API

## Outcome

Make the 0.5 SDK release easier to adopt and operate without expanding the
architecture. Server, Work, and third-party Rust applications continue to use
the same Core, Engine, SDK, run lifecycle, Skill service, and Worker protocol.

## Scope and evidence

| Gate | Deliverable | Completion evidence |
|---|---|---|
| SDK adoption | A short integration checklist, failure guide, and compiling downstream fixture for `minimal`, `standard`, and `full`. | Website build, generated-doc check, and `scripts/ci/check_sdk_consumers.sh`. |
| Work Agent experience | Keep the existing local Model, Agent context, Workspace, and diagnostics settings as the single Agent configuration surface. | `microclaw-work` check and Work application tests. |
| Skill trust | Show source, version, availability, and runtime enablement in Work; retain governed import and recoverable archive. | Runtime Skill tests plus Work compilation. |
| Subagent operation | Retain one visible Main Agent, read-only Subagents, progress/result/error projection, and cancellation. | Work runtime and application tests. |
| Worker recovery | Preserve bounded reconnect, ordered replay, duplicate suppression, pending-control resend, and host-side single execution. | Engine remote Worker and WebSocket Worker tests. |
| Release efficiency | Ordinary CI does not repeat a cold release-profile build after clippy/tests; artifact workflows remain the release-build authority. | Workflow review plus CI run. |
| Publication | Publish `microclaw-core`, `microclaw-engine`, and `microclaw-sdk` together as 0.5.1, then run a registry consumer smoke test. | crates.io API, `sdk-v0.5.1` tag, publish workflow, and registry smoke job. |

## Compatibility boundaries

- No breaking change to the 0.5 SDK API or Worker protocol.
- No new public crate and no dependency from reusable crates back to Server or Work.
- No named Agent teams, arbitrary nested Agent graph, or second orchestration loop.
- No new Skill marketplace; GitHub and ClawHub remain import sources.
- Root Server/Work product versions are independent from the Rust SDK patch.

## Release sequence

1. Land documentation, Work metadata, tests, and CI changes.
2. Run formatting, SDK boundaries/consumers, workspace tests and clippy, Web and
   documentation builds, and the SDK packaging check.
3. Tag the verified commit `sdk-v0.5.1`.
4. Publish Core, wait for the index, publish Engine, wait, then publish SDK.
5. Verify immutable registry consumers and publish the GitHub release notes.
6. Mark this plan Delivered and remove local build artifacts.

## Release evidence

- Source commit: `7167775`
- Tag and GitHub release: [`sdk-v0.5.1`](https://github.com/microclaw/microclaw/releases/tag/sdk-v0.5.1)
- Publication workflow: [run 33910165698](https://github.com/microclaw/microclaw/actions/runs/33910165698)
- crates.io: [`microclaw-core`](https://crates.io/crates/microclaw-core/0.5.1), [`microclaw-engine`](https://crates.io/crates/microclaw-engine/0.5.1), and [`microclaw-sdk`](https://crates.io/crates/microclaw-sdk/0.5.1)
