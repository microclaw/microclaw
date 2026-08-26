# MicroClaw Work macOS execution plan

Status: **active**  
Updated: **2026-08-26**

This document is the current delivery plan for MicroClaw Work. It narrows the
older cross-platform proposal to one supported desktop product: macOS. Windows
and Linux remain possible future ports, but their compatibility, packaging,
and acceptance work must not delay the first complete macOS product.

MicroClaw Server remains a separate, supported product. Work and Server share
the provider-neutral Agent Engine, tools, safety policy, memory, storage, and
configuration types. Work must not copy the Agent Loop or weaken Server tests.

## Product completion definition

MicroClaw Work is complete for its first macOS release when a new user can:

1. install the app without a terminal;
2. configure a model, `SOUL.md`, project context, and appearance in Settings;
3. create, find, reopen, and continue durable conversations;
4. connect a project, run a real task, steer or stop it, and recover after exit;
5. inspect plans, approvals, commands, diffs, and artifacts;
6. accept or revert project changes safely;
7. update or uninstall the app through Homebrew; and
8. run the unchanged Server build and test matrices independently.

Compatibility with unreleased Work snapshot formats is not a release blocker.
Before the first stable release, schema changes may replace transitional data
instead of carrying permanent migration branches. Existing Server user data,
credentials, permissions, and safety boundaries remain protected.

## Stage 1 — Native foundation

Status: **complete**

- GPUI + GPUI Component native shell and branded macOS bundle;
- shared Work application and runtime service boundaries;
- conversation-first layout, native composer, recent conversations, and
  persistent session snapshots;
- shared Agent Engine execution, streaming, stop, retry, steering, and restart
  recovery;
- native model onboarding, diagnostics, dark/light/system appearance, and
  application menu shortcuts.

Evidence lives in the Phase 0/1 reports and the dated macOS smoke report.

## Stage 2 — Daily work loop

Status: **in progress; core loop complete**

Delivered:

- project-folder connection with a safe private Work Home fallback;
- Agent-authored plans, tool activity, process verification, approvals,
  subagent activity, multi-file diffs, artifacts, checkpoints, accept/revert,
  and same-thread follow-up;
- Settings for local `SOUL.md` identity and project-context directory;
- searchable durable conversation history by title or Workspace;
- stable creation-time conversation ordering with Pin / Unpin in each row's
  right-click menu;
- named conversation controls and a repeatable macOS Accessibility-tree audit;
- left-aligned conversation rows and a compact equal-width Workspace utility
  toolbar;
- native macOS IME marked-text, candidate selection, draft persistence, and
  relaunch recovery verified in an isolated Work data directory;
- progressive long-conversation rendering and bounded large-diff persistence
  and previews;
- a reproducible maximum-size session benchmark with local save/load budgets
  recorded in
  [the dated scale report](../reports/microclaw-work-session-scale-2026-08-26.md);
- shared current-model presets and editable custom provider configuration;
- recoverable conversation storage that preserves damaged snapshots for
  diagnosis and rebuilds valid history;
- user-facing recovery for malformed Work-owned configuration that preserves
  the original file and never replaces an external Server configuration;
- real Codex-account smoke coverage for completion, cancellation, retry,
  approval, project changes, revert, and relaunch persistence.

Remaining acceptance work:

- sustained use with long multi-tool conversations;
- direct VoiceOver speech acceptance;

Stage exit: seven consecutive days of daily macOS use without conversation
loss, unsafe project mutation, or a required terminal workaround.

## Stage 3 — macOS release

Status: **implementation complete; release credentials pending**

Delivered:

- branded `.app` and DMG builders;
- Hardened Runtime, Developer ID, notarization, stapling, signature, launch,
  and DMG verification paths;
- GitHub release and Homebrew Cask publication automation;
- a desktop-only distribution profile that does not change Server release
  settings.

Remaining release work:

- run the public candidate with the production Developer ID and notary profile;
- install that candidate on a clean macOS user account;
- publish one prerelease and verify Homebrew install, upgrade, and uninstall;
- record rollback instructions and final checksums.

Stage exit: the published Homebrew Cask installs a notarized app, completes a
real first task, upgrades in place, and leaves Server artifacts unaffected.

## Stage 4 — Work and Server connection

Status: **planned after the standalone macOS release**

- explicit device pairing with revocable credentials;
- remote task submission, progress, cancellation, approvals, and artifacts;
- clear local-versus-remote execution and permission scope in the UI;
- Server-owned scheduling and background survival;
- protocol tests that preserve identity, budget, audit, and cancellation.

This stage does not introduce a hosted multi-tenant cloud or a free-form
multi-agent canvas. The first target is a Work client connected to a
user-owned MicroClaw Server.

## Deferred scope

- Windows and Linux binaries, installers, signing, and UI compatibility;
- native mobile clients;
- a second desktop Agent Loop;
- plugin marketplace and complete IDE/terminal emulation;
- multi-tenant SaaS;
- arbitrary multi-agent topology editing.

These items require a separate product decision after the macOS standalone
release has daily-use evidence.
