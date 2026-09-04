# Roadmap documents — index

These files accumulate; without a status column a reader cannot tell a delivered
plan from an aspirational one. **The active plan is the single entry marked
`Active` below.** Everything marked `Delivered` or `Superseded` is kept for
history — do not pick work from it without checking against the active plan
first.

| Document | Status | Notes |
|---|---|---|
| [`sdk-v0.5.1-plan.md`](./sdk-v0.5.1-plan.md) | **Active** | Patch-release execution plan: SDK adoption, Work Skill provenance, Worker recovery evidence, and leaner release gates. |
| [`work-server-local-first-plan-2026-08.md`](./work-server-local-first-plan-2026-08.md) | Strategic reference | Canonical Server + local-first Work direction; the active patch release takes only its bounded 0.5.1 slice. |
| [`product-direction-2026-08.md`](./product-direction-2026-08.md) | Superseded | Original direction that established the two-product boundary; replaced by the focused local-first delivery plan. |
| [`microclaw-work-macos-execution-plan.md`](./microclaw-work-macos-execution-plan.md) | Superseded | macOS execution baseline; remaining gates are carried into the active local-first plan. |
| [`microclaw-work-proposal-cn.md`](./microclaw-work-proposal-cn.md) | Proposal | Chinese proposal for the next major Work/Server product boundary; discussion only, not implementation authorization. |
| [`next-direction-2026-08.md`](./next-direction-2026-08.md) | Superseded | Full-tree health review; open maintenance findings remain useful inputs to the active product direction. |
| [`db-decomposition-plan.md`](./db-decomposition-plan.md) | Delivered | Split `db.rs` (17k lines / 237 methods) into domain modules behind the same facade; shipped in 0.5.0. |
| [`v0.4.0-plan.md`](./v0.4.0-plan.md) | Delivered | v0.4.0 shipped 2026-08-07; exit criteria met, `v0.4-lts` branch cut. |
| [`v0.3.0-completion-and-v0.4.0-kickoff.md`](./v0.3.0-completion-and-v0.4.0-kickoff.md) | Delivered | Superseded by the v0.4.0 plan. |
| [`v0.3.0-self-improving-runtime.md`](./v0.3.0-self-improving-runtime.md) | Delivered | v0.3.0 workstream. |
| [`non-web-channel-progress-events-plan.md`](./non-web-channel-progress-events-plan.md) | Delivered | Shipped as the event tap + progress heartbeat. |
| [`feature-completion-pr-plan.md`](./feature-completion-pr-plan.md) | Delivered | Per-PR checklist still referenced by other docs. |
| [`feature-completion-tracking-board.md`](./feature-completion-tracking-board.md) | Reference | Standing per-PR checklist. |
| [`stability-usability-roadmap-2026-q3.md`](./stability-usability-roadmap-2026-q3.md) | Superseded | Folded into the v0.4.0 plan. |
| [`stability-tracking-board-2026-q1.md`](./stability-tracking-board-2026-q1.md) | Historical | Q1 2026 board. |
| [`durable-secure-runtime-2026-07.md`](./durable-secure-runtime-2026-07.md) | Historical | Design input to v0.4.0. |
| [`capability-deepening-2026-h2.md`](./capability-deepening-2026-h2.md) | Aspirational | Not scheduled; ideas only. |
| [`competitive-landscape-and-direction-2026-h2.md`](./competitive-landscape-and-direction-2026-h2.md) | Reference | Positioning, not a work plan. |
| [`competitive-intel-update-2026-08.md`](./competitive-intel-update-2026-08.md) | Reference | Latest competitive scan. |
| [`competitive-intel-update-2026-07.md`](./competitive-intel-update-2026-07.md) | Historical | Previous scan. |
| [`../roadmaps/sandbox-adoption-plan-2026-02.md`](../roadmaps/sandbox-adoption-plan-2026-02.md) | Delivered | Sandbox shipped; note the singular `roadmaps/` directory is legacy. |

## Conventions

- One `Active` document at a time. When a new plan opens, mark the previous one
  `Delivered` or `Superseded` in the same commit.
- The public-facing roadmap lives at [`site/docs/roadmap.md`](../../site/docs/roadmap.md).
  It is what visitors read, so it must not carry shipped work as future work.
