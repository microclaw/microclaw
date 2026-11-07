# Roadmap documents — index

These files accumulate; without a status column a reader cannot tell a delivered
plan from an aspirational one. When an entry is marked `Active`, it is the only
current execution plan. Everything marked `Delivered` or `Superseded` is kept
for history — do not pick work from it without checking whether a newer active
plan exists first.

| Document | Status | Notes |
|---|---|---|
| [`next-plan-2026-11-cn.md`](./next-plan-2026-11-cn.md) | Active | Plan after 0.23.0: finish the 0.23.0 release, test with real models and ship 0.23.1, then the MicroClaw Code UX release (0.25, which absorbs the planned 0.24 and 0.26) and parallel tracks for VS Code, Windows ARM and a Windows sandbox. |
| [`mccode-desktop-plan-2026-11-cn.md`](./mccode-desktop-plan-2026-11-cn.md) | Proposed | MicroClaw Code desktop app for macOS in Rust + GPUI (`gpui-component` 0.9 / `gpui-pre`, crates.io only): an in-process front end over `microclaw-code-core`'s `Control`/`Update` driver, sharing `~/.mccode` and sessions with the CLI; compares it with Zed (ACP Registry integration: yes; forking Zed or linking its GPL-3.0 crates: no); 0.27 ships the Zed/ACP integration plus M0, which unifies session wiring in `code-core::launch` plus a GPUI spike, M1 (0.28) preview DMG, M2 (0.29) release, M3 parallel worktree tasks. |
| [`mccode-ux-config-plan-2026-11-cn.md`](./mccode-ux-config-plan-2026-11-cn.md) | Delivered (0.25.0) | MicroClaw Code parity and innovation plan for configurability, interaction and the TUI, compared with Claude Code, Codex CLI, OpenCode 2.x and Kimi Code CLI: theme tokens, Markdown/syntax/diff rendering, queue vs steer, layered settings with allow/ask/deny rules, Claude-compatible hooks, approvals pushed to chat channels, per-turn receipts, hunk-level review; delivered together as 0.25. |
| [`v0.26.0-plan.md`](./v0.26.0-plan.md) | Delivered | MicroClaw Code as a separate product: `~/.mccode`, `MCCODE_*` variables only, no shared model configuration or environment with the Server, no compatibility shims. |
| [`v0.25.0-plan.md`](./v0.25.0-plan.md) | Delivered | MicroClaw Code interaction and configuration release (planned 0.24–0.26 in one): themeable TUI, queue vs steer, layered settings with allow/ask/deny rules, Claude-compatible hooks, approvals in chat channels, per-turn receipts, hunk review. |
| [`v0.23.1-plan.md`](./v0.23.1-plan.md) | Delivered | First real-model (DeepSeek) test pass over MicroClaw Code: approval resume, compaction on small windows, LSP, images, export, worktree hints. |
| [`mccode-next-plan-cn.md`](./mccode-next-plan-cn.md) | Delivered (0.21–0.23) | Next MicroClaw Code plan after 0.20.0: comparison with Claude Code, Codex CLI, OpenCode and Kimi CLI; token-based context engine (pruning, structured incremental compaction, `/context`), model-driven context tools, LSP, hooks, Windows sandbox. |
| [`microclaw-code-proposal-cn.md`](./microclaw-code-proposal-cn.md) | Delivered | MicroClaw Code (`mccode`) product line and its five batches (#527–#531); section 10 lists open ideas. |
| [`v0.23.0-plan.md`](./v0.23.0-plan.md) | Delivered | Context engine, model-managed context and the 0.21–0.23 MicroClaw Code features in one release. |
| [`v0.20.0-plan.md`](./v0.20.0-plan.md) | Delivered | First MicroClaw Code (`mccode`) release: terminal coding agent, OS sandbox, verification, ACP/MCP, separate packages and install scripts. |
| [`v0.11.1-plan.md`](./v0.11.1-plan.md) | Delivered | Security patch: global `tool_policy.allow_tools` is a real allowlist with wildcards, the tool catalog is filtered by policy, and doctor / config check flag an empty policy. |
| [`v0.11.0-plan.md`](./v0.11.0-plan.md) | Delivered | Web UI dependency release: `@assistant-ui/react` 0.15 without the tap pin, tool-call cards with arguments, Playwright browser smoke test in CI. |
| [`v0.10.1-plan.md`](./v0.10.1-plan.md) | Delivered | Web UI hotfix: pin `@assistant-ui/tap` to 0.9.12 so the composer no longer crashes on the first keystroke (#517). |
| [`v0.9.0-plan.md`](./v0.9.0-plan.md) | Delivered | Dependency release shipped: matrix-sdk 0.19 with rustls TLS, rusqlite 0.40, Rust 1.96 toolchain. |
| [`v0.8.0-plan.md`](./v0.8.0-plan.md) | Delivered | Multi-user hardening release shipped: governance file guard for file tools, `write_memory` row dedup, Telegram partial-quote forwarding. |
| [`v0.7.0-plan.md`](./v0.7.0-plan.md) | Delivered | Prompt-cache stability release shipped: byte-stable prompt prefix, request-time turn context, and prompt-cache usage accounting. |
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
