# Changelog

All notable changes to this project should be recorded in this file.

The format is loosely based on Keep a Changelog. Dates use UTC.

## Unreleased

### Added

- MicroClaw Code in Zed (`mccode acp`) now speaks ACP protocol v1 with schema
  1.15: mode and model selectors (session config options), slash commands
  (`/review`, `/compact`, `/undo`, `/cost`, `/context`, `/help` and custom
  commands), the context and cost indicator, real file diffs with old and new
  text, absolute paths so Zed can follow the agent, project checks as their
  own tool cards, thread titles and history (`session/list`, resume, close),
  notices and compaction updates, and a sign-in prompt that runs
  `mccode setup` in a terminal when no model is configured.
- `scripts/acp_registry_entry.py` writes the ACP Registry entry for a release
  (`packaging/acp-registry/`).

### Fixed

- `mccode acp` and `mccode mcp-server` use model profiles from
  `settings.yaml`; before, they required a configuration file and stopped at
  startup without one. They also apply `permissions.default_mode`,
  `disabled_modes` and the project's compaction settings.
- `mccode config show` and `config get` no longer print API keys; they show
  `sk-…abcd`.
- `mccode acp` lists every project's sessions when `session/list` has no
  `cwd`, so Zed's "Import Threads" finds them; before, it returned none.

### Changed

- Engine setup for every Code front end lives in
  `microclaw_code_core::launch`.
- `docs/schema/code-settings.v1.json` is written with sorted keys, so it is
  the same whichever crates share the build.

## 0.26.0 - 2026-11-06

MicroClaw Code becomes a fully separate product from the MicroClaw Server.
After upgrading, run `mccode setup` (or add a model profile to
`~/.mccode/settings.yaml`); an old `~/.microclaw/code` is not read.

### Changed

- **MicroClaw Code is fully separate from the MicroClaw Server.** Its home
  moves from `~/.microclaw/code` to `~/.mccode` (nothing is migrated: move the
  old directory by hand to keep settings and sessions). Code no longer
  borrows model credentials from `MICROCLAW_CONFIG` or
  `~/.microclaw/microclaw.config.yaml`: it uses `--config`, `MCCODE_CONFIG`,
  `~/.mccode/config.yaml` or a settings profile. Its variables are
  `MCCODE_HOME`, `MCCODE_CONFIG`, `MCCODE_SANDBOX`, `MCCODE_MANAGED`,
  `MCCODE_LOCAL_SANDBOX`, `MCCODE_PATH_ALLOWLIST` and `MCCODE_REPO` (the old
  `MICROCLAW_CODE_*` names are no longer read), and Server variables such as
  `MICROCLAW_CONFIG`, `MICROCLAW_SKILLS_DIR` and `MICROCLAW_LOCAL_SANDBOX`
  no longer affect it. Managed settings move to `/etc/mccode/managed.yaml`
  (macOS `/Library/Application Support/mccode/managed.yaml`, Windows
  `%ProgramData%\mccode\managed.yaml`). The OS sandbox hides `~/.mccode`
  from shell commands, like `~/.microclaw`.
- Documentation and the `mccode config init` template keep role models on the
  session's profile, and say that `model.roles.subagent` is not used yet.

## 0.25.0 - 2026-11-06

The MicroClaw Code interaction and configuration release. The planned 0.24
(TUI), 0.25 (settings and permissions) and 0.26 (innovations) ship together;
see `docs/roadmap/mccode-ux-config-plan-2026-11-cn.md`.

### Added

- **TUI look**: theme tokens with truecolor, 256- and 16-colour fallback;
  11 built-in themes, user YAML themes and OpenCode theme files; Markdown
  replies with syntax highlighting; diffs with line numbers, word-level
  highlights and a side-by-side layout on wide terminals; consecutive reads
  and searches grouped into one "Explored" row; a side panel for the plan,
  checks, changed files and running sub-agents; a per-item render cache; an
  inline mode that uses the terminal's own scrollback (`tui.screen: inline`,
  falling back to full screen when the terminal does not report the cursor).
- **TUI interaction**: Enter queues a message while the agent works and
  Ctrl+S steers the running turn; fuzzy `/` and `@` pop-ups and a Ctrl+P
  palette; per-project prompt history with Ctrl+R search; Ctrl+G edits in
  `$EDITOR`; `!` runs a shell command yourself; large pastes become a chip;
  Ctrl+V attaches a clipboard image; Ctrl+T opens the transcript with search;
  Esc Esc rewinds the files to an earlier turn; model, theme (live preview)
  and session pickers; mouse scrolling and click-to-expand; desktop
  notifications (OSC 9/777) when the terminal is unfocused; rebindable keys
  (`tui.keymap`, `/keys`).
- **Per-turn receipts** (files, checks, sandbox and network use, tokens, cost
  when the price is known, checkpoint), **hunk-level review** on F2 (revert a
  hunk, or turn comments into a prompt), **`/goal`** (keep going until a
  condition holds and the checks pass), **`/btw`** (a side question in a copy
  of the session) and **`/configure`** (describe a settings change; the model
  proposes it and you confirm).
- **Layered settings** for MicroClaw Code: user, project, local and managed
  YAML layers with a JSON schema (`docs/schema/code-settings.v1.json`) and
  per-key provenance; `mccode config show|get|set|unset|paths|doctor|init|schema|migrate|edit`;
  `mccode import claude|codex|opencode`; provider profiles that can replace
  the configuration file; per-role models (`plan`, `review`, `summary`).
- **Permission rules** (`allow` / `ask` / `deny` for `bash`, `read`, `edit`,
  `net`, `mcp`, `agent`, `tool`; Claude Code spellings accepted) and **hooks**
  compatible with the Claude Code protocol (ten events; exit code 2 blocks;
  `permissionDecision`, `updatedInput`, `additionalContext`). Both are
  enforced through a new engine `ToolGate` (SDK `MicroClawBuilder::tool_gate`),
  so sub-agents go through them too. ACP and MCP-server modes load the same
  settings.
- **Approvals and notifications in chat**: with a paired Server, MicroClaw
  Code sends approval cards (buttons on Telegram, Discord and Slack; numbered
  options on Feishu) and "done" notifications while you are away
  (`notify.chat`); Server endpoints `/api/code/notify` and
  `/api/code/approvals`.
- SDK: `MicroClawBuilder::summary_model`; the `ToolGate` types are re-exported.

### Fixed

Found by testing this release with DeepSeek (`deepseek-flash`,
`deepseek-v4-pro`):

- The shell tool ran commands in the login shell (`$SHELL`); zsh aborts on an
  unmatched glob such as `grep --include=*.rs`. Commands now run in bash when
  it is installed (Server and Code).
- `bash_kill` stopped only the shell, so a child (a dev server under
  `npm run dev`) kept running and the process stayed "running". Background
  commands now run in their own process group and are stopped as a group.
- Role models sent `profile/model` to the provider as the model name; an
  `ask` rule could be answered by auto mode; `-p 1` after a pause looped when
  a prompt hook added context to the answer.

### Changed

- Writing `.microclaw/settings.local.yaml` adds it to the repository's
  `.git/info/exclude`.
- `scripts/generate_docs_artifacts.mjs` leaves `#[serde(skip)]` config fields
  out of the generated defaults.

### Security

- vodozemac 0.11.2 (Matrix end-to-end encryption), which restores secret
  zeroization (RUSTSEC-2026-0445, published on release day).

### Known gaps

Ctrl+B does not move a running command to the background (it toggles the
side panel); Esc Esc rewinds files but not the conversation; there is no
sub-agent role model; model presets carry no prices; `read(...)` rules do not
cover shell commands and `net(...)` rules cover `web_fetch` only.

## 0.23.1 - 2026-11-05

Fixes found by running MicroClaw Code against real models (DeepSeek
`deepseek-flash` and `deepseek-v4-pro`) on the eval cases and by hand.

### Fixed

- **Approvals resumed later were not understood**: answering a paused
  approval with `1`/`2` or `3` in a later turn (`mccode --session <id> -p 1`,
  the MCP `run` tool, and the Telegram / Discord / Slack / web option cards)
  reached the model as a bare digit, which some models did not read as an
  approval. The reply is now rewritten into an explicit instruction to retry
  (or not run) the paused call.
- **Compaction never ran with small context windows**: the verbatim tail kept
  by a Code compaction (24k tokens) did not shrink with the target, so a
  session on a small window (a local model, an eval case) could not be
  compacted at all and ran into a context overflow. The tail is now capped at
  half of the compaction target.
- **DeepSeek V4 windows**: `deepseek-v4-pro` and `deepseek-flash`
  (`deepseek-v4-flash`) are counted as 1M-token models instead of 128k.
- **Language-server diagnostics**:
  - pyright never published diagnostics because MicroClaw Code did not send
    `workspace/didChangeConfiguration`;
  - a server on `PATH` that cannot start (rustup's `rust-analyzer` proxy
    without the component) was shown as a passing check; it is now reported
    once with an install hint and skipped;
  - a server that sends nothing in time is reported as not checked;
  - when diagnostics were the only check, a fix round that made them pass
    still ended `-p` with exit code 1.
- **`@image` mentions followed by punctuation** (`@shot.png?`, `@shot.png。`)
  were not attached.
- **`mccode export`** failed without a terminal ("the interactive interface
  needs a terminal").
- **`--worktree` summary** suggested `git merge` while the changes were still
  uncommitted in the worktree; it now says to commit them first.
- **Repositories without a `.gitignore`**: `review` lists at most 100
  untracked files (the rest counted per directory), and the per-turn change
  fingerprint no longer reads every large untracked file.

### Changed

- `mccode eval`: `min_compactions` in `case.yaml` fails a case that did not
  compact; the long-session cases use windows above the fixed prompt size so
  they really compact, and the compaction count no longer races the run.

### Security

- hyper 1.12.0, which drops the unmaintained `pin-utils`
  (RUSTSEC-2026-0441, published on release day).

## 0.23.0 - 2026-11-05

### Added

- **Images**:
  - `@path/to/image.png` in a MicroClaw Code prompt attaches the image
    (PNG, JPEG, GIF, WebP, up to 5 MB); Zed and other ACP clients can paste
    images (image prompt capability);
  - SDK: run metadata `image` (`IMAGE_METADATA`) and
    `HeadlessRunRequest::image`.
- **Worktree tasks**: `mccode --worktree [name]` runs a session in a new git
  worktree on branch `mccode/<name>` and prints how to review, merge or
  remove it; `mccode worktree list|remove`.
- **Pull request review**: `mccode review --pr N [focus] [--post]` reviews a
  PR's diff (`gh pr diff` or `origin` `refs/pull/N/head`) and can post the
  findings with `gh pr comment`.
- **Export**: `/export [file]` and `mccode export [--out file]` write a session
  as Markdown.
- **Token budget**: `--max-session-tokens` / `max_session_tokens` stop a
  session before the next request once the budget is used.
- **Anthropic context editing** (`anthropic_context_editing`, beta):
  server-side clearing of old tool results (`clear_tool_uses_20250919`) on
  top of local compaction.

### Changed

- MicroClaw Code states the sandbox situation per platform. On Windows there
  is no OS sandbox: commands ask first in `ask` mode, and `auto` mode without
  a sandbox shows a warning.


- **Model-managed context**:
  - with `context_budget_hint` (on in coding workspaces), the model sees how
    full its context is on every request; the note rides on the newest
    message, so the prompt cache is unaffected;
  - experimental `context_note` / `rewind_context` tools (`context_tools`,
    `mccode --context-tools`): the model checkpoints its own context and
    rewinds it, with a note to itself, dropping failed attempts.
- **`explore`**: a read-only helper with its own context that answers wide
  questions and returns a short report. Several calls run in parallel.
  Project agents in `.microclaw/agents/<name>.md` (front matter
  `description`, `model`) are offered to it in trusted projects
  (`explore_tool`, `project_agents_dir`).
- **Handoff**: SDK `MicroClaw::handoff_session` and `mccode /handoff <task>`
  start a new session from a summary focused on the next task.
- MicroClaw Code:
  - **project memory**: `.microclaw/memory.md`, loaded in trusted projects
    and kept up to date by the agent with the file tools;
  - **custom slash commands** from `.microclaw/commands/*.md` and
    `~/.microclaw/code/commands/*.md`, with `$ARGUMENTS` (also in `-p`);
  - **language-server diagnostics** (rust-analyzer,
    typescript-language-server, pyright, gopls) after edits, handed back like
    a failed check (`lsp: false` disables them);
  - **project hooks** `after_edit` / `after_turn`.


- **Token-aware context management** (all products). Each request is
  measured against the model's context window (known models are recognized by
  name; `model_context_window` / `model_context_windows` override it).
  Compaction starts at `context_pressure_compact_pct` (now 80, at most 90) of
  the usable window and runs in stages:
  - first, older tool outputs are cleared without a model call
    (`prune_protect_tokens`, `prune_minimum_tokens`), and a file read again
    later replaces the earlier read;
  - then older history becomes a structured, incremental summary (goal and
    constraints, decisions, files and state, errors and fixes, plan,
    verification, next step) that keeps the user's own earlier messages
    verbatim and lists the files changed;
  - long histories are summarized in chunks instead of being cut at 20,000
    characters.
- `compact_instructions`, `auto_compact` and `compact_keep_recent_tokens`
  settings. `max_session_messages: 0` compacts by tokens only.
- `RuntimeEvent::ContextCompacted` (runtime event schema 7). The Web stream
  publishes it as `context_compacted`.
- SDK: `MicroClaw::context_usage`, `compact_session_with(…, focus)`,
  `ContextUsage`, `SessionCompaction`, and the builder options
  `compact_instructions` and `context_window`.
- MicroClaw Code:
  - `/context` (window, compaction point and token breakdown);
  - `/compact <focus>`;
  - a `ctx N%` indicator in the status bar;
  - compaction notices in the TUI and in `-p` output;
  - `compact_instructions` in `.microclaw/project.yaml`.
- `mccode eval`:
  - multi-turn cases (`followups`) and a `context_window` override;
  - a `compactions` count per case;
  - two long-session cases (`long-session-recall`, `long-session-steps`).

### Changed

- When the summarizer fails, compaction keeps a mechanical digest (earlier
  summary, user requests, files changed, last commands) instead of dropping
  the older history.
- A turn stops compacting after two pressure compactions that cannot reduce
  the conversation further.
- The conversation is archived before mid-turn and overflow compactions too.
- SDK workspaces (MicroClaw Code):
  - compaction is by tokens, keeping about 24k tokens verbatim;
  - tool results are inlined up to 60,000 characters (previously 4,000), so
    whole source files reach the model and old outputs are pruned later
    instead of being truncated up front.

## 0.20.0 - 2026-11-04

### Added

- **MicroClaw Code** (`mccode`, `apps/microclaw-code`, Preview): a terminal
  coding agent and one of the three products, next to the Server and the SDK.
  It reaches the Agent Engine only through `microclaw-sdk`, and CI forbids a
  direct engine dependency. It has:
  - a full-screen TUI: streamed replies, tool calls, coloured diffs, plan
    checklists, and dialogs for approvals, project trust and executing a
    plan; `@file` / `/command` completion, steering while the agent works,
    and Shift+Tab mode switching;
  - `-p` one-shot runs with `--json` JSON Lines output and exit codes
    0 / 1 / 2 (2 = approval pending; resume with `--session <id> -p 1|3`);
  - `plan` / `ask` / `auto` permission modes, where auto still asks for
    destructive shell commands;
  - automatic verification with the project's checks (Rust, Node, Python,
    Go, Make) whenever a turn changed the git working tree, including
    through shell commands, with failures handed back for a bounded number
    of fix rounds;
  - `.microclaw/project.yaml`, honoured only after the user trusts that
    exact file content;
  - its own home, `~/.microclaw/code`, holding config, engine data,
    sessions and trust decisions, separate from a Server's `~/.microclaw`;
  - `setup`, `doctor`, `check`, `init`, `info`, `sessions` and `trust`
    subcommands; `microclaw code …` forwards to `mccode`.

  - in-run approvals: the TUI answers an approval inside the running turn
    (the engine waits) instead of starting a new run with "1/2/3";
  - per-project command allow rules ("always allow `cargo test` in this
    project"), limited to single simple commands, via the approval dialog,
    `/allow` and `mccode allow`;
  - resuming a session (`-c`, `--session`) shows its earlier messages;
  - `/undo` and `/rewind` (workspace checkpoints taken at every turn),
    `/review` and `mccode review` (read-only review of the uncommitted
    changes), `/model`, `/cost`, `/compact` and `/fork`;
  - trusted projects load `AGENTS.md` (or `CLAUDE.md` / `AGENT.md`) into the
    agent's instructions;
  - shell commands run in the OS sandbox by default (bubblewrap / Seatbelt):
    writes are limited to the repository, temp and tool caches, and
    credential directories are hidden. Use `--sandbox off` and
    `--no-network`; `mccode doctor` and `/status` show the state. With
    network off, ask mode runs sandboxed commands without asking;
    `--review-commands` lets a model flag dangerous commands (asked even in
    auto mode);
  - `mccode acp` (Agent Client Protocol for editors such as Zed, with
    permission requests, modes and session loading) and `mccode mcp-server`
    (tools `run` and `review`);
  - `mccode remote pair|status|forget` and `mccode -p … --remote`: hand a task
    to a paired MicroClaw Server and stream the result;
  - `mccode eval` (cases with a snapshot, a prompt and a check) and
    `mccode eval replay` (cases from bug-fix commits);
  - releases ship `mccode` as its own archive (`mccode-<version>-<target>`)
    with its own Homebrew formula (`brew install microclaw/tap/mccode`;
    `microclaw` installs only the Server), and `mccode update` installs the
    latest release after
    checking `SHA256SUMS.txt`.

  The UI-independent core (project discovery, trust, verification, session
  index, turn driver) is `crates/microclaw-code-core`. Proposal:
  `docs/roadmap/microclaw-code-proposal-cn.md`.
- In-run approval suspension in the Agent Engine: an embedding caller that
  sets the `interactive_approvals` run metadata (SDK: `INTERACTIVE_APPROVALS`)
  gets `ApprovalRequired` with a live `approval_id` and answers it with
  `RuntimeControl::ResolveApproval` / `RunController::resolve_approval_confirmed`
  (`1`/`approve`, `2`/`always`, `3`/`deny`); the same run then retries the
  tool, records the standing grant, or returns a denied tool result to the
  model. The headless executor now reports `approvals: true`. Channels and
  callers without the opt-in keep the text approval path. Decisions are
  audited (`in_run_decision`).
- `microclaw-sdk` (`full`) adds `MicroClaw::session_messages(session, limit)`
  for showing a session's history, plus per-session `checkpoint` /
  `checkpoints` / `restore_checkpoint`, `session_usage`, `session_model` /
  `set_session_model`, `compact_session` and `fork_session`.
- `approval_channels` (default `[web, code]`) and
  `read_only_subagent_channels` (default `[code]`) replace hard-coded channel
  names in the approval gate and the sub-agent restriction.
- `run_agent_turn(state, AgentTurn)` is the single entry point of the agent
  loop; the `process_with_agent*` functions are shorthands for it.
- `bash_input`: write to a background process's stdin (REPLs, debuggers,
  prompts) and read what it answers.
- In-run approvals accept `defer`, which ends the run with the text approval
  prompt (non-interactive callers).
- Landlock fallback for `sandbox.backend: local` on Linux without
  bubblewrap.
- `sandbox.backend: local`: the operating system's sandbox (bubblewrap on
  Linux, Seatbelt on macOS) as a container-free alternative to
  Docker/Podman. It allows writes to the working directory, temp, tool caches
  and `sandbox.writable_roots`, hides credential directories, and unshares
  the network when `no_network` is set. Unlike container backends it also
  confines `run_in_background` processes. `microclaw doctor` checks it. SDK:
  `MicroClawBuilder::shell_sandbox(ShellSandbox::…)` and `local_sandbox()`.
- `apply_patch` engine tool: add, delete, move and edit several files in one
  atomic call (`*** Begin Patch` format); every operation is checked,
  including the stale-read guard, before anything is written. It is a
  workspace tool (Medium risk), and each changed file streams a `FileDiff`
  event (new `file_diffs` result metadata for multi-file diffs).
- `microclaw-sdk` (`full`) exposes `model_providers()` and
  `validate_config_file()`.
- `bash` gains `run_in_background`, with new `bash_output` (incremental,
  filterable output) and `bash_kill` tools. Processes are scoped to the
  session and owned by the tool registry, which kills them when it is
  dropped. They are refused while the sandbox is on.
- `edit_file` accepts `edits[]` (several replacements applied
  all-or-nothing) and `replace_all`.
- `ToolPolicy::WorkspaceWrite` now has a meaning: the Agent Profile is
  offered workspace tools only, and calls to anything else are refused.
- ACP (`microclaw acp`) streams tool calls with kind, status and location,
  plus file diffs and plan updates. It also shows replies that only arrive
  as the final response, such as approval prompts.

### Changed

- `glob` and `grep` respect `.gitignore` / `.ignore` files, also outside a
  git checkout. `include_ignored: true` restores the old traversal, and
  `glob` falls back to a literal match when nothing visible matches.
- `edit_file` and `write_file` refuse to overwrite a file that changed on
  disk after the agent last read or wrote it (`stale_read`).
- In a direct workspace (`working_dir_isolation: direct`), `bash` runs in
  the workspace root instead of its `tmp/` subdirectory.
- The high-risk approval gate and the read-only sub-agent restriction apply
  to the `code` caller channel (`HeadlessRunRequest::code`,
  `{cancel,steer}_code_session`, `CODE_CHANNEL`).

## 0.11.1 - 2026-10-25

### Security

- `tool_policy.allow_tools` is now a real allowlist. Before, the global
  list was only an *exemption* from `deny_tools` / `max_risk`, so a config
  such as `mode: block, allow_tools: [read_file]` with no deny list
  restricted nothing, and the catalog sent to the model was never filtered
  by the policy, so the agent kept being offered tools the operator believed
  were off. Reported privately by nilo (nilo85). Now:
  - a non-empty global `allow_tools` blocks (or warns about, under
    `mode: warn`) every tool not listed; an empty list keeps the old
    "no allowlist" meaning;
  - `deny_tools` wins over `allow_tools`, and `max_risk` applies to
    allow-listed tools too, so each rule only ever removes tools;
  - global `allow_tools` / `deny_tools` accept `*` and trailing wildcards
    (`mcp_*`), as grant lists already did; previously a wildcard in a
    global list silently matched nothing;
  - the tool catalog sent to the model (main loop and sub-agent loop) is
    narrowed to what the policy lets the caller run
    (`ToolRegistry::definitions_for`); the choke point in
    `execute_with_auth` still enforces the policy on every call;
  - `microclaw doctor` gains a `security.tool_policy` check and
    `microclaw config check` warns when `tool_policy.mode` is on but
    `allow_tools`, `deny_tools` and `max_risk` are all empty.

  Operators who relied on the old exemption semantics (listing a tool in
  `allow_tools` to lift a `deny_tools` or `max_risk` rule for it) must
  remove it from `deny_tools` or raise `max_risk` instead.

### Removed

- Dependabot version-update configuration (`.github/dependabot.yml`). The
  grouped cargo and npm bump PRs were more noise than signal; dependency
  updates are now done deliberately per release, as the 0.10.1 and 0.11.0
  security updates were.

### Changed

- Web UI browser smoke test: one `microclaw` server per test instead of per
  worker, and the reload test waits until the server has stored the message
  (via `/api/history`) and navigates with `?session=` before asserting, so a
  slow provider round-trip on CI can no longer race the reload.

## 0.11.0 - 2026-10-25

### Added

- Web UI browser smoke test (`web/e2e`, Playwright): boots the built
  binary with a generated web-only config, signs in, types and sends in the
  real embedded composer, then reloads and types again; any uncaught browser
  error fails it. A new `Web UI Browser Smoke` CI job runs it on every push,
  so the first-keystroke crash class from #517 (shipped unnoticed in v0.8.0
  to v0.10.0) is now caught before release. `cargo build && npm --prefix
  web run e2e` runs it locally (#522).

### Changed

- Web UI: moved to `@assistant-ui/react` 0.15 (0.15.31) with
  `@assistant-ui/react-markdown` 0.14.24. `@assistant-ui/react-ui` has no
  release that works with 0.15 (it still imports `useThread`, see #496), so
  the chat thread is now built directly on the `@assistant-ui/react`
  primitives, keeping the same `aui-*` class names, a vendored base
  stylesheet (`web/src/assistant-ui.css`) and the existing look and
  behaviour (tool-call cards, think-segment disclosure, timestamps, approval
  button bar, no attachments or message editing). This retires the
  `@assistant-ui/tap` 0.9.12 override in `web/package.json` and the three
  assistant-ui Dependabot ignores from 0.10.1 (#517).

### Fixed

- Web UI: tool-call cards never appeared during a run. The server publishes
  `call_id` and `preview` on `tool_start` / `tool_result` stream events, but
  the chat adapter still looked for `tool_use_id` / `output` and dropped the
  events; both key names are accepted now, and `tool_start` also carries the
  tool `input` so the card shows the arguments.

## 0.10.1 - 2026-10-24

### Fixed

- Web UI: the first keystroke in the message composer threw
  `Maximum update depth exceeded` and froze the page (#517). The 2026-10-05
  dependency bump let the transitive `@assistant-ui/tap` float to 0.9.20,
  whose `getSnapshot` loop guard fires against the unfixed
  `@assistant-ui/core` 0.2.23 that the 0.14 line is frozen on; v0.8.0,
  v0.9.0 and v0.10.0 all shipped that pair. `web/package.json` now pins
  `@assistant-ui/tap` to 0.9.12 through `overrides`, and Dependabot holds it
  there until the UI moves to `@assistant-ui/react` 0.15.

### Security

- Targeted dependency updates for advisories published after 0.10.0:
  ctutils 0.4.5 (RUSTSEC-2026-0385), rustls-webpki 0.103.16
  (RUSTSEC-2026-0382), tokio 1.54.1 (RUSTSEC-2026-0386), webpki-root-certs
  1.0.11 (RUSTSEC-2026-0383) and webpki-roots 1.0.11 (RUSTSEC-2026-0381).

## 0.10.0 - 2026-10-18

### Added

- Server device pairing. The Web console's
  Access tab mints single-use pairing codes; `POST /api/pairing/claim` trades
  a code for a hashed, revocable device token (`operator.read` +
  `operator.write`, actor `device:<id>`), listed and revoked under
  `/api/pairing/devices`, with `GET /api/pairing/whoami` for clients to verify
  their identity. `POST /api/runs/:run_id/cancel` cancels one run over HTTP.

### Changed

- Schema v44 adds the `paired_devices` table (automatic migration).

### Security

- zip 2 → 9 with only the deflate feature (RUSTSEC-2026-0367/0368/0369; the
  ClawHub installer never used `ZipArchive::extract`), rustls 0.23.46
  (RUSTSEC-2026-0346..0349) and quinn-proto 0.11.19
  (RUSTSEC-2026-0338/0340/0343).

## 0.9.0 - 2026-10-07

### Changed

- Unified website, CLI help, Snap contact, and all localized README Discord
  links with the shared XNU community invite.
- `@assistant-ui/react-markdown` 0.14.7 in the web UI.
- The optional Matrix channel (`channel-matrix`, included in `full`) moved from
  matrix-sdk 0.16 to 0.19. Its TLS backend is now rustls with aws-lc
  (`rustls-aws-lc-rs`, matrix-sdk 0.19 dropped `native-tls`), and building it
  needs Rust 1.96. The pinned toolchain moves to 1.96.1; the workspace MSRV
  stays 1.93 for builds without Matrix (#510).
- rusqlite moved from 0.37 to 0.40 across the workspace (matrix-sdk-sqlite 0.19
  links the same `sqlite3`). `microclaw-core`'s optional `sqlite-errors`
  feature exposes `MicroClawError::Database(rusqlite::Error)`, so SDK consumers
  that match on that variant or convert their own rusqlite errors need
  rusqlite 0.40 too.

### Security

- matrix-sdk 0.19 fixes RUSTSEC-2026-0318 (matrix-sdk-crypto to-device panic)
  and, through imbl 7, RUSTSEC-2026-0292 (imbl-sized-chunks) and drops the
  unmaintained `bitmaps` (RUSTSEC-2026-0247); their audit/deny exceptions are
  removed. `anymap2` (RUSTSEC-2026-0319) is still pulled in by matrix-sdk 0.19
  and stays ignored.

## 0.8.0 - 2026-10-05

### Changed

- `microclaw-engine` `Config` gained the public `allow_governance_file_writes`
  field (default `false`). Code that builds `Config` with a struct literal must
  set it.

### Security

- `write_file` and `edit_file` now refuse to modify MicroClaw's own governance
  files: the active config file, `AGENTS.md` / `SOUL.md` / `USER.md` under the
  data directory, `souls_dir`, `context_dir` (and chat-scoped `context/`
  folders), configured `soul_path`s and the path allowlist. Previously these
  tools sidestepped the `write_memory` scope checks, so a prompt-injected agent
  could plant global memory that reached other users' chats (#501). Set
  `allow_governance_file_writes: true` to restore the old behavior. This guards
  the file tools only; `bash` without the sandbox still runs as the service
  user.

### Fixed

- `write_memory` no longer appends a duplicate structured memory row on every
  save. Rows store the first 180 characters of the written content, and
  global/bot writes resend the whole file, so repeated saves produced
  byte-identical rows. An existing live row with the same content is now
  refreshed in place (archived history is left alone); re-saving without
  `ttl_days` makes the fact durable again (#505).
- Telegram replies that quote part of a message now forward the selected text
  to the agent, and cross-chat quotes forward their text instead of nothing
  (#506).
- Dependency updates (cargo patch/minor groups, web dev dependencies).
  Dependabot now holds `@assistant-ui/react` below 0.15 and
  `@assistant-ui/react-markdown` below 0.14.8, which `@assistant-ui/react-ui`
  cannot use yet.
- Security Audit ignores RUSTSEC-2026-0318 and RUSTSEC-2026-0319: both come
  from matrix-sdk 0.16 behind the non-default `channel-matrix` feature, and the
  affected code path is not reachable. They are removed with the matrix-sdk
  0.19 upgrade (#510).

- Removed the retired `Build (Release)` job from the release finalizer CI gate,
  which made the Homebrew tap update wait until it timed out.

## 0.7.0 - 2026-09-29

### Changed

- `microclaw-core` `Usage` gained the public `cache_read_input_tokens` and
  `cache_creation_input_tokens` fields. Code that builds `Usage` with a struct
  literal must set them or use `..Default::default()`.

### Fixed

- Stabilized the cached prompt prefix so prompt caching actually takes effect
  across turns. The live clock, query-matched memories, ranked skill bodies,
  mood read, verified prior experiences, plugin context, and relationship hint
  moved out of the system prompt into a transient `<turn_context>` block that
  is attached to the latest user message at request time and never persisted,
  leaving the system prompt and the stored history byte-identical between turns.
- Stabilized plugin tool ordering by sorting manifests by name, so the tool
  definitions in the cached prefix no longer reshuffle between restarts.
- Rendered stored message timestamps in `<user_message ts="...">` at whole-second
  UTC precision, so re-rendering an unchanged history produces identical text.

### Added

- Added `system_prompt_time_detail` config (`none` / `date` / `full`), defaulting
  to `date`, controlling how much clock detail the system prompt carries.
- Added prompt-cache token accounting (`cache_read_input_tokens` and
  `cache_creation_input_tokens`) to LLM usage, provider response parsing, and
  agent metrics, so cache effectiveness is observable per run.

## 0.6.1 - 2026-09-04

### Changed

- Added reusable per-platform release caches and a bounded timeout for Server
  release builds, reducing repeated patch-release compilation time.
- Updated official artifact, Docker, and Nix actions to their current Node
  24-based major versions.
- Updated the public Rust SDK install examples and release guide to the stable
  `0.6.1` release.

### Fixed

- Restricted GitHub Release aggregation to distributable Server, and
  reliability artifacts so Docker Buildx's internal `.dockerbuild` records
  cannot break the final upload step.
- Added a strict release manifest check that rejects missing or unexpected
  Server and reliability assets before checksums or publication.
- Corrected the documentation home page release badge and link, which still
  referenced v0.5.5 after the v0.6.0 release.
- Added a release-version guard for public SDK snippets and stable-version
  references across the README files and documentation home page.

## 0.6.0 - 2026-09-04

### Added

- Added a CI release invariant that keeps Server, Core, Engine, SDK, and web package metadata on one
  product version.
- Extended the release asset CI guard to accommodate cold Docker and stability
  builds without timing out a healthy tagged release.
- Added durable, observable, and cancellable Main Agent delegation with
  stable SDK projections for delegated tasks.

### Changed

- Aligned the complete MicroClaw product and Rust workspace at 0.6.0.
- Formalized the single-writer Workspace model: Subagents can perform bounded
  parallel work while the Main Agent retains approvals, mutation ordering,
  cancellation, and the final response.
- Kept Server on one SDK and Agent Engine execution path while
  preserving the SDK's `minimal`, `standard`, and `full` dependency tiers.

## Rust SDK 0.5.1 - 2026-09-04

### Added

- Added a first-integration acceptance checklist and failure-recovery guidance
  to the SDK quickstart.

### Changed

- Removed the redundant cold `cargo build --release` job from ordinary CI;
  release-profile builds remain part of the artifact release workflow.
- Updated the three public Rust crates together to 0.5.1 without changing the
  0.5 public API.

## 0.5.0 - 2026-09-04

### Added

- Added live SDK Skill lifecycle APIs for refresh, enable/disable, governed
  local/GitHub/ClawHub installation, and recoverable removal.
- Added stable SDK projections for observing and cancelling durable tasks
  delegated by the Main Agent.
- Added configurable remote Worker reconnect attempts and backoff.

### Changed

- SDK Skill imports now share one Engine service with staged local
  copies, symlink rejection, injection scanning, and path-safe Skill names.

## 0.4.0 - 2026-09-04

### Added

- Added stable `SdkErrorCode` classification and graceful `Runtime::shutdown`
  lifecycle support for embedded hosts.
- Added a post-publication registry smoke test that downloads the immutable SDK
  release and verifies `minimal`, `standard`, and `full` consumers.

### Changed

- Made Core HTTP and SQLite error conversions opt-in compatibility features.
  Protocol-only SDK consumers no longer compile Reqwest, SQLite, Tokio, Typst,
  OpenTelemetry, or the Agent Engine.
- Moved the Typst/PDF renderer behind the Engine `document-tools` feature.
  `standard` SDK hosts avoid that dependency graph, while `full` and Server
  retain document generation.
- SDK errors no longer expose `RuntimeBuildError` as a public enum payload.

## 0.3.0 - 2026-09-04

### Changed

- Consolidated reusable runtime, storage, tool, channel, observability, ClawHub,
  and Worker implementations into `microclaw-engine`, removing eight duplicate
  implementation crates from the workspace.
- Replaced the public `microclaw_engine::internal` namespace with explicit
  Engine integration modules used by Server.
- Made SDK presets real dependency tiers: `minimal` is protocol-only,
  `standard` adds the embeddable runtime, and `full` adds configured Engine and
  Skill discovery.
- Updated SDK documentation and release validation for the 0.3 crates.io set.

### Added

- **Programmatic full-SDK configuration.** Rust hosts can now initialize the
  complete Agent Engine with `FullRuntimeConfig` and `MicroClaw::configure`
  without creating a Server-oriented YAML file.
- **Downstream SDK compatibility fixture.** CI now compiles a standalone Rust
  application outside the MicroClaw workspace against the `minimal`,
  `standard`, and `full` SDK feature presets and executes the minimal preset.

- **Embeddable Rust runtime foundation.** `microclaw-core` now defines stable
  Agent, Run, control, capability, and Worker contracts. The new
  `microclaw-runtime` crate owns reusable run handles, event streaming,
  cancellation, steering, concurrency, and Local Worker execution, while
  `microclaw-sdk` provides a small third-party facade and compiling example.
  The versioned remote Worker protocol covers discovery, health, submission,
  resumable events, controls, acknowledgements, and terminal results.
- **SDK-first Agent and Skill API.** `microclaw-sdk` now provides stable
  `MicroClawBuilder`, `MicroClaw`, `AgentBuilder`, and `SkillCatalog` entry
  points, validates selected Skills before execution, and reports setup
  failures through SDK-owned errors instead of leaking Engine internals.
- **Operational Local Workers.** Local Workers now report active and queued
  runs, support labels, draining, resume, unavailable state, and waiting for
  idle. Submission returns an explicit error when a Worker has stopped
  accepting work instead of creating an ambiguous failed run.
- **Transport-neutral Remote Worker client.** The SDK can discover a versioned
  remote Worker, validate frame and run identity, stream its events into a
  normal `RunHandle`, forward acknowledged controls, refresh health, and map
  terminal frames into the same result contract used by Local Workers.
- **Authenticated WebSocket Worker transport.** The new `microclaw-worker`
  crate hosts Local or custom Workers over WebSocket, uses constant-time Bearer
  token checks, and provides an SDK transport for discovery, health, events,
  controls, and terminal results without pulling Server or UI dependencies into
  the Worker boundary.

### Changed

- **Public Rust SDK 0.2.0.** The crates.io surface is now intentionally limited
  to `microclaw-core`, `microclaw-engine`, and `microclaw-sdk`. Runtime,
  persistence, tools, channels, observability, bundled Skills, ClawHub, and
  Worker implementation now ship inside the Engine package; application and
  migration-only workspace crates are marked non-publishable.

- **SDK-first project documentation.** The README and public documentation now
  present Server and the Rust SDK as three explicit entry points. The
  website gives each path a separate, color-coded quickstart card instead of a
  mixed installer, with reduced-motion-safe entrance and interaction animation,
  and gives the SDK first-class navigation plus task-focused
  guides for setup, lifecycle contracts, Skills, Workers, and feature/crate
  selection.

- **Publishable Rust SDK crate set.** Reusable crates now carry crates.io
  metadata, and a protected manual workflow publishes them in dependency order
  with exact version checks, duplicate-release handling, and index propagation
  waits before publishing `microclaw-sdk`. After the initial release, the same
  workflow blocks SemVer-incompatible public API changes before publication.

- **Resumable remote Worker runs.** WebSocket-hosted runs now survive client
  disconnects, retain ordered events for protocol resume, and treat repeated
  submissions with the same run ID as one execution. Remote SDK clients
  reconnect automatically and suppress already-delivered events.
- **Bounded Worker replay memory.** Worker hosts retain at most 256 completed
  runs and 4,096 events per run by default, expose configurable replay limits,
  and return an explicit retryable error when requested history has expired.

- **Removed redundant nightly build.** The scheduled Nightly Stability workflow
  duplicated the required stability-smoke job and a metrics test already run by
  the main test suite, so it no longer consumes a daily runner or creates noisy
  failure issues.

- **One execution lifecycle for every product surface.** Server channels, Web,
  ACP, Scheduler, and headless now enter Agent execution through the same
  `RunRequest`, `RunHandle`, and `RunResult` path. Runtime controls support
  explicit acceptance or rejection instead of reporting only queue delivery.
- **Effective embedded Agent profiles.** SDK Agent profiles now apply their
  custom system prompt, explicit Skill selection, and read-only tool policy to
  the real shared Agent Engine.
- **Physical Agent Engine library boundary.** The concrete provider-neutral
  Agent loop and its default runtime services now compile in
  `microclaw-engine`. Server re-exports that shared implementation, while SDK
  full depends on the Engine crate without pulling in the root Server
  product package, Web console, or concrete channel adapters.

## 0.5.1 - 2026-08-26

### Fixed

- **Codex streamed final-text recovery.** The OpenAI Codex Responses parser now
  retains `response.output_text.delta`/`done` text when the terminal
  `response.done` payload omits visible output. This prevents a successfully
  authenticated ChatGPT-backed Codex run from falling through to the Agent
  Engine's empty-reply retry and completion fallback.

## 0.5.0 - 2026-08-16

### Added

- **Plan mode.** `/plan` (or the ACP `plan` session mode) restricts the agent
  loop to read-only tools and presents a plan; an approving reply re-runs the
  work with the full toolset.
- **Headless one-shot CLI.** `microclaw run -p "<prompt>" [--session <name>]
  [--json]` runs a single prompt with no channels attached.
- **API-key pool rotation.** `api_keys` (top-level or per provider profile)
  forms a round-robin pool that rotates on 401/403/429 responses.
- **Per-chat model and provider overrides.** `/model here <name>` and
  `/provider here <alias>` scope an override to one chat.
- **Context-pressure compaction.** Mid-turn compaction triggers at
  `context_pressure_compact_pct` of `model_context_window`, with
  compact-and-retry on provider context-overflow errors. The compaction split
  is tool-block aware.
- **Interactive approval buttons.** High-risk approval option cards render as
  native buttons on Telegram, Discord, Slack, and web; a tap re-enters the
  existing text approval-parsing path.
- **`AfterTurn` hook event and opt-in self-recheck.** `self_recheck.enabled`
  adds a one-pass post-edit review before finalizing.
- **File-edit diffs and progress reporting.** `edit_file`/`write_file` attach a
  unified diff to tool metadata, forwarded to web SSE and to chat behind
  `file_diffs_in_chat`. Non-web channels gained a throttled edit-in-place
  progress heartbeat with a percent bar, live sub-agent count, and optional
  message pinning.
- **Reply-quote forwarding.** Replying to an earlier message prepends
  `[quoted from <author>: …]` on Telegram, Discord, and Weixin.
- **Group-concise soul preset.** `examples/soul/group-concise.md` tunes replies
  for busy group chats.

### Changed

- **Website and README refresh.** The public homepage now highlights the current
  release, project descriptions and skill counts match the v0.5.0 runtime, the
  roadmap is recast as durable project direction, and obsolete Docusaurus
  starter assets and internal iteration pages are removed.

- **Monolith source files decomposed.** The five remaining oversized files
  are split into domain modules behind unchanged import paths: `src/llm.rs`
  (5,280 lines -> provider/translation/resilience modules), `src/setup.rs`
  (11,276 -> eleven wizard modules), `src/web.rs` (6,775 -> state/dto/route
  modules alongside the existing submodules), `src/config.rs` (5,387 -> eight
  config domains), and `db/learning.rs` (6,923 -> experience/skills/tracks).
  All moves are verbatim with pub(crate) visibility promotions only; test
  counts are unchanged.
- **Storage layer decomposed.** `crates/microclaw-storage/src/db.rs` (17,178
  lines, 237 public methods in one `impl` block) is split into 14 domain
  modules under `db/` (chats, sessions, tasks, subagents, memory, learning,
  usage, auth, audit, outbox, turns, tool cache, runtime meta, schema) behind
  the unchanged `Database` facade. All moves are verbatim; public API,
  migration history, and test counts are identical, and no consumer code
  changed.
- **Web UI build moved to vite 8 and React 19**, closing the remaining
  build-tooling advisories (vite path traversal, esbuild dev-server origin).
  The bundle is now split into `react`, `markdown`, and `vendor` chunks instead
  of one ~957 kB file, so the assets embedded in the binary cache
  independently.
- **Web UI frontend decomposed.** `web/src/main.tsx` (4,927 lines, 61% of the
  frontend) is split into `lib/` modules (think-tag extraction, backend types,
  config model, session helpers, SSE parsing) and per-concern components
  (chat thread, config controls, all settings tabs); `main.tsx` is now 2,373
  lines with identical behavior, verified end-to-end against a running
  backend.
- **Docs site dark theme rebuilt for contrast.** The page, section, and card
  tones previously sat within ~5% lightness with card shadows disabled, which
  read as one flat grey field; they now form a deliberate lightness ladder with
  visible card edges. Site default color mode is `light` (an explicit OS
  preference still wins).
- **Web operator UI visual system refreshed.** The embedded console now uses a
  consistent surface, border, type, and elevation system across dark, light,
  and accent themes. The session sidebar, active-session state, runtime header,
  settings navigation, dialogs, forms, and mobile layout have clearer visual
  hierarchy without changing their behavior or API contracts.

### Fixed

- **A clean clone now builds on Node 22 LTS.** `web/package.json` pinned
  `engines.node` to `24.x` while `web/.npmrc` sets `engine-strict=true`, so the
  unconditional `npm ci` in `build.rs` aborted `cargo build` on any other Node
  major — including in `snap/snapcraft.yaml`, which pulls `node/22/stable` and
  therefore could not build the snap at all. The pin is now `>=22`.
- **`check.sh` no longer passes silently on failure.** It had no `set -e`, so it
  ran past failing steps and exited with the last command's status. It also
  still invoked `npm --prefix website`, left over from the `website/` → `site/`
  move, as did `deploy.sh` and five release checklists.
- **CI now builds the web UI and docs site on both supported Node LTS majors**,
  the gap that hid the `engines` break.

## 0.4.0 - 2026-08-07

### Added

- **Web approval option cards.** The web chat renders a paused high-risk
  approval as clickable option buttons (approve once / always allow / deny)
  driven by the structured `approval_required` stream event; clicking sends
  the same numbered reply the text contract defines.
- **Reliability scorecard publication.** Every release attaches
  `reliability-scorecard-<tag>.{json,md}` (the proof-pack results generated
  from the tagged source) to its GitHub release assets; CI uploads the same
  scorecard per push, and a docs page covers scope, schema, and one-script
  reproduction.
- **ClawHub load-time integrity verification.** Managed skills are
  re-verified against their lockfile tree hash whenever skills load.
  `clawhub_verify_on_load` (default `block`) hides tampered skills and fails
  activation with an actionable message; unpinned pre-hash installs warn
  instead of blocking.
- **Consolidated status surface.** `/status` and the web governance
  snapshot/panel report scheduler DLQ depth, 24h contract verdicts,
  token-budget usage, provider failover/circuit-breaker health, and
  supervised-loop restart counters.
- **Opt-in webhook alerts.** A supervised loop POSTs JSON alerts on DLQ
  growth, provider down, budget exhaustion, and restart storms — baseline
  first poll, per-class cooldowns, egress-governed webhook, audit-chained
  deliveries. Off by default.
- **Opt-in periodic trust report.** A digest of task runs, contract
  verdicts, token spend, guardrail audit events, and reliability health
  delivered to control chats on a restart-surviving cadence. No LLM calls;
  off by default.
- **Structured approvals.** High-risk approval prompts are numbered option
  cards (approve once / always allow in this chat / deny) with en/zh
  keywords; "always" records an audit-chained standing per-chat grant
  managed via the new `/approvals` command, and web clients receive a
  structured `approval_required` stream event. An opt-in
  `aux_models.approval_reviewer` annotates prompts with an advisory verdict
  and never decides.
- **MCP/A2A trust tiers.** Per-server (`trust: trusted|limited|sandboxed`
  in `mcp.json`) and per-peer (`a2a.peers.<name>.trust`) tiers map onto
  tool-policy risk; omitted = `limited` = historical behavior, `sandboxed`
  requires explicit approval.
- **Model-swap canary.** `microclaw canary <model>` probes a candidate
  model (response + tool-calling) through the exact configured provider
  path before an operator switches `model:`.
- **User message language.** `user_message_language` (`en` default / `zh` /
  `bilingual`) selects the language of approval prompts and token-budget
  refusals via a new message catalog.
- Plugin-host runtime decision recorded as RFC 0007 (hold RFC 0006's
  supervised Node host; reserve wasmtime for a future compute-skill
  surface), plus an OWASP agentic top-10 self-assessment and a published
  tokens-per-task benchmark method with extraction script.

### Changed

- Replaced the green MicroClaw identity with a blue cyber-claw mark across
  repository and documentation-site assets, and refreshed the public site's
  palette, typography, cards, controls, favicons, PWA icons, and social card.
- Reworked the root README files into concise project entry points, moved
  setup and integration detail into task-focused documentation, and added
  localized overview and quick-start pages for 10 widely used languages.

## 0.3.5 - 2026-08-01

### Changed

- Dependency maintenance now checks Cargo and Web npm updates weekly after a
  seven-day cooldown, keeps GitHub Actions on a predictable monthly schedule,
  and splits large update groups by SemVer level or dependency type. Web UI,
  CI, nightly, and release builds now require Node.js 24.x and enforce package
  engine compatibility during npm installs.

## 0.3.4 - 2026-07-31

### Added

- **Learning Foundry.** Durable user-directed learning tracks run bounded,
  read-only research epochs on a cron schedule and produce source-backed,
  test-bearing skill candidates. Candidates remain inert until an
  administrator explicitly promotes them; existing skills continue to require
  comparative reflection and shadow evidence for changes.
- **Learning Foundry evaluator.** New candidates run paired no-tool
  baseline/candidate scenarios, persist token use, latency, evidence and
  regressions, and fail closed unless evaluation improves on baseline before
  manual promotion.

## 0.3.3 - 2026-07-30

### Added

- **Reliability Proof Pack.** `scripts/ci/reliability_scorecard.sh` now exercises
  recovery, scheduler replay, durable delivery, payload integrity, rate-limit
  recovery, command timeout, malformed provider wrappers, output sanitization,
  cross-chat permissions, and sandbox fail-closed behavior. It emits a
  machine-readable JSON scorecard, a linked Markdown report, and per-scenario
  logs; the existing Stability Smoke release gate runs the proof pack.
- **Contract-governed deep research workflow.** The new built-in
  `deep-research-workflow` skill decomposes broad questions into distinct
  parallel research packages, requires source ledgers and completion
  contracts, runs an adversarial verifier, and reports citation coverage,
  source independence, conflict disposition, unsupported claims, and a final
  PASS/FAIL verdict before synthesis.

### Fixed

- Database schema v41 repairs incomplete historical `scheduled_tasks`
  migrations even when `db_meta.schema_version` was already advanced. Existing
  databases missing `exit_criteria`, `run_count`, `max_runs`, `not_after`, or
  `timezone` are repaired on open before scheduler queries execute.

## 0.3.2 - 2026-07-28

### Added

- **Comparative reflection and governed skill evolution.** Comparable
  success/failure runs now produce versioned, counterexample-bearing learning
  claims and immutable candidate skill patches. Paired shadow observations
  gate promotion using risk-adjusted utility, cost, and regression thresholds;
  promoted candidates automatically roll back to the previous trusted version
  on verified regression. Web and CLI Learning Journals expose evidence,
  impact scope, evaluation state, and undo actions.
- **Failure-aware retrieval and skill recovery.** Verified failures and active
  task-scoped skill contraindications are excluded from prompt injection while
  their rejection reasons remain visible in the Learning Journal. Structured
  failure patterns track environment, tool, error category, cooldown, recovery
  trials, and automatic resolution from verified successes.
- **Task-signature and risk-adjusted skill evaluation.** Experience runs now
  carry a deterministic v1 task type, task family, capability tags, and stable
  signature hash, with schema-v38 backfill for existing history. Skill quality
  is aggregated overall and per task family with a configurable Wilson lower
  bound. Trial promotion requires both raw success and conservative utility;
  applicability and verified-experience retrieval now incorporate task
  compatibility, capability overlap, and utility rather than relying only on
  text and environment matches.
- **Verified long-horizon learning substrate.** Agent turns now produce durable
  goal, experience-run, verifier-evidence, skill-version, and attributed
  skill-outcome records. Governed skills progress through
  `candidate -> trial -> trusted`, degrade on verified regressions, can be rolled
  back to a recorded version, and are blocked when repeated failures establish
  an environment-specific contraindication. `/usage` and Web learning APIs
  expose the evidence and lifecycle; users can attach human feedback to a run.
  Experience records also capture token, model-request, tool, error, duration,
  and estimated-cost metrics. Strongly verified prior runs are recalled for
  similar tasks as untrusted historical evidence. Multiple human reviews are
  confidence-aggregated, expiring evidence is excluded, ambiguous multi-skill
  credit cannot govern skills, and an admin-scoped policy controls promotion
  and degradation thresholds. All evidence producers now enter through a
  versioned outcome envelope, human corrections have a normalized
  `experience_feedback` projection, and retrieval audit logs identify every
  prior experience injected into a run. `/learning [run_id]` and the
  run-detail Web API expose the experiences used, activated skills, and
  supporting evidence for an individual run.
- **Durable coworker checkpoints.** Interactive agent turns now persist
  provider-neutral message snapshots at safe model/tool-result boundaries. Fresh safe
  checkpoints resume automatically after restart; interruptions during tool execution
  stop with progress/tool evidence and never blindly replay an uncertain side effect.
  `/status`, Web Governance, and `turn_recovery` audit events expose the lifecycle.
- **Scoped secure-runtime policy.** Tool authorization can now apply least-privilege
  grants by chat, channel, and principal (main, scheduler, channel, or subagent), with
  global policy blocks remaining authoritative. A central egress policy validates
  configured endpoints and tool-input HTTP(S) destinations, including private/metadata
  address blocking and host allow/deny lists.
- **Sandbox credential isolation.** Dotenv files are no longer forwarded wholesale to
  containers. Credential-like variables are withheld by default and require an exact
  `sandbox.credential_env_allowlist` entry. Doctor/config self-check and Web Governance
  expose the new capability, egress, and credential posture.
- Added RFC 0006 for TypeScript-authored plugins: deterministic locked builds,
  supervised stdio JSON-RPC host, per-plugin principals, mediated filesystem/network/
  secret APIs, container isolation, and a phased SDK/runtime/distribution plan.
- Added `scripts/trigger_release.ps1` so Windows operators can validate and trigger the audited
  tag plus native Windows, macOS, Linux, checksum, and container release workflows with one command.
- Added the equivalent `scripts/trigger_release.sh` entry point for macOS and Linux release operators.
- **Durable chunk-level outbound delivery.** User-visible channel messages are now persisted before
  the first network call and tracked as independently retryable chunks. Interrupted sends resume
  from the unfinished chunk after restart, the full logical reply is stored exactly once, and
  Weixin reuses a stable native `client_id` for safe retries. Scheduler runs distinguish immediate
  delivery from durable queued acceptance instead of duplicating the full message in the outbox.
- **Shared user-visible output sanitization.** Final channel delivery strips private reasoning tags
  and textual tool-call traces at the common delivery boundary, including scheduler and tool-driven
  messages, so runtime protocol details do not leak into Weixin or other chat channels.
- **`microclaw doctor delivery`.** A read-only diagnostic now reports durable-ledger totals,
  unfinished chunks, retry state, oldest unfinished work, and terminal delivery failures without
  sending a test message or exposing credentials.
- Long channel replies now preserve newline bytes at chunk boundaries, so concatenating delivered
  chunks reconstructs the sanitized logical reply exactly instead of losing one newline per split.

- **Output guardrail (credential leak protection).** A new `output_guardrail` config block
  (`mode: off | redact | block`, default **off**) scans outbound bot messages for credential-like
  strings (OpenAI/Anthropic keys, GitHub PATs, AWS keys, Slack/Google tokens, Bearer tokens, PEM
  private-key blocks, `api_key=` assignments) before they are delivered. `redact` masks the secret
  and still delivers; `block` withholds the message. Applied both to each channel's main reply and
  to the shared tool/scheduler delivery path, so a secret echoed from tool output, memory, or the
  model can't leak to a chat. Detection reuses `microclaw-core`'s `redact` module, split so the
  outbound path strips **credentials only** (emails/phone numbers the bot legitimately sends are
  left intact). Every trip is logged to the `output_guardrail` trace target.
- **Pluggable web-search backends.** `web_search` (and the new `deep_research` tool) can now run
  against DuckDuckGo (default, no key), a self-hosted **SearXNG** instance, **Brave Search**, or
  **Tavily** — selected via the new `web_search` config block (`backend`, `searxng_base_url`,
  `brave_api_key`, `tavily_api_key`, `max_results`). Defaults preserve the historical DuckDuckGo
  behavior exactly, and a backend selected without its credentials/endpoint transparently
  degrades to DuckDuckGo instead of failing.
- **`deep_research` tool** — a deterministic multi-source research pass: fans out several
  sub-queries across the configured search backend, deduplicates sources, concurrently fetches the
  top pages through the existing SSRF-guarded `web_fetch` path, and returns a citation-numbered
  evidence digest with source-agreement signals (corroboration across sub-queries, coverage gaps).
  Semantic cross-verification and synthesis are left to the agent reading the digest, so the tool
  runs no LLM and is fully deterministic. Available to the main agent and to research sub-agents.

### Changed

- Clearer channel auth-failure logs — when a channel can't start because its credentials are
  rejected, Telegram/Discord/Slack/Feishu now log an actionable message ("authentication
  failed … check the token / run `microclaw setup`") instead of a generic or silent error,
  so a bad token isn't mistaken for the bot just going quiet. Part of the usability push.

### Fixed

- Built-in skill frontmatter now parses consistently from LF and CRLF checkouts, so
  platform and dependency gates no longer install incompatible skills on Windows.
- Release verification tests now use platform-native commands, paths, and symlink
  capabilities across Windows and Unix hosts.

### Added

- More guidance in the CLI: after `microclaw setup` succeeds it now prints the next steps
  (`microclaw doctor` → `microclaw start`, with a note about `doctor --online`); and
  `microclaw eval --help`, `microclaw audit --help`, and `microclaw doctor --help` each end
  with an Examples section. (`doctor --help` now routes to the doctor parser so its options and
  examples actually show.) Part of the usability push.
- Setup wizard now labels every field `[required]` or `[optional]` (previously only required
  fields were marked, leaving "unmarked" ambiguous), so it's obvious at a glance what must be
  filled before saving. Part of the usability push.
- `microclaw --help` now ends with an **Examples** section (setup, doctor, `doctor --online`,
  start, `skill audit`, `audit verify`, `eval`) and a pointer to per-command `--help`, so the
  common workflows are discoverable without reading docs. Part of the usability push.
- `microclaw doctor` now checks that the data and working directories can be created and
  written to — the most common "won't start" cause (read-only path, wrong permissions, a
  typo'd `data_dir`). Reports each as ✅ writable or ❌ with the failure reason and a fix hint.
  Part of the usability push.
- Setup wizard now refuses to save a config with no channel enabled — the source-side fix for
  "configured a channel but forgot `enabled: true`". Clearing all channels blocks save with a
  clear instruction instead of producing a config that fails to start. (The field defaults to
  `web`, so a normal setup is unaffected.) Part of the usability push.
- `microclaw doctor --online` — verifies the LLM credentials by sending a minimal "hi" request
  to the configured provider (reusing the setup wizard's probe), so a bad API key or model is
  caught at preflight instead of surfacing as a confusing failure on the first chat. Rejected
  credentials are a ❌ FAIL with a fix hint; a network/transient failure is a ⚠️ WARN (so an
  offline run isn't falsely red); `openai-codex` is skipped (external auth). Without `--online`,
  `doctor` stays hermetic and notes that credentials weren't verified. Part of the usability push.
- Clearer "no channel enabled" diagnostics — the common trap of filling in a channel's
  credentials but forgetting `enabled: true` now produces an actionable message instead of a
  generic one: the config error (and `microclaw start`) name the configured-but-disabled
  channels and tell you to set `channels.<name>.enabled: true`. `microclaw doctor` now (a)
  actually loads & validates the config (previously it only checked the file exists, so an
  invalid config showed a misleading green), and (b) reports which channels are enabled plus
  warns about any configured-but-disabled ones. Part of the usability/onboarding push.
- Friendlier config parse errors — when `microclaw.config.yaml` fails to parse, the message now
  appends an actionable pointer (edit and re-run, or `microclaw setup`, plus a link to the
  annotated example config), and for an unknown field/variant (a mistyped key like `discrod`)
  it suggests the closest valid name ("did you mean `discord`?"). The original serde error
  with its line/column is preserved. Part of the usability/onboarding push.
- In-chat `/help` command (aliases `/commands`, `/?`) — lists every slash command with a
  one-line description, grouped by area (session & context, model & provider, skills,
  memory & usage). There was previously no way to discover the 15+ commands from inside a
  chat. The CLI quick-start (`microclaw --help`) now points new users to it. First of a
  usability/onboarding push.
- Per-task auxiliary models: a new `aux_models` config section lets a (typically
  cheaper) model handle ancillary work. Wired slots:
  - `aux_models.compaction` — context/history summarization.
  - `aux_models.reflector` — the background memory reflector (fact/triple extraction),
    which runs periodically per active chat.
  - `aux_models.title` — one-shot session-title generation.
  - `aux_models.vision` — image description (the `describe_image` tool); overrides
    `media.vision.model` when set, and an explicit per-call `model` argument still wins.

  (`session_search` has no LLM step — it is pure full-text search — so it has no slot.)
- Tamper-evident audit log — every new `audit_logs` entry is now sealed into a SHA-256
  hash chain (`entry_hash` over the entry's fields plus the previous entry's `entry_hash`,
  with a genesis link for the first). Modifying a field, deleting a row, or reordering rows
  breaks the chain. A new `microclaw audit verify` command walks the chain and reports the
  first broken link (exiting non-zero so it can gate monitoring/CI), and `microclaw audit
  list [--kind] [--limit]` prints recent entries. Sealing happens under the DB connection
  lock so concurrent writers can't race the chain; pre-migration rows stay unsealed and are
  simply excluded from verification. First slice of the v0.4.0 security-governance track
  (tamper-evident audit).

  Each auxiliary model reuses the main provider profile and credentials — only the
  model name is swapped — and falls back to the main model when unset, so default
  behavior is unchanged. First steps toward the v0.3.0 "Self-Improving Runtime" plan
  (`docs/roadmap/v0.3.0-self-improving-runtime.md`).
- Sleep-time memory consolidation (`sleep_time`, off by default) — when a chat has been
  idle for a while, a background loop runs a deterministic (no-LLM) pass that archives
  near-duplicate same-category memories, so the store stops accumulating redundancy
  between reflector runs. PROFILE (identity) memories are never touched, archiving is
  reversible, and the pass is throttled per chat (`min_interval_hours`) and capped
  (`max_archived_per_pass`). First slice of the v0.3.0 sleep-time consolidation (Pillar 1c).
- `microclaw eval` subcommand — a deterministic trajectory-evaluation gate for recorded
  agent sessions, with no LLM call. It replays a session fixture (a JSON array of
  messages, or an object with a `messages` array) and checks trajectory health:
  no dangling `tool_use`, no orphaned `tool_result`, the session ends on a real answer
  (not a raw `tool_result`), tool-call count within `--max-tool-calls`, and tool errors
  surfaced (failing only under `--strict-tool-errors`). It also flags **stuck loops**
  (the same tool + arguments repeated `--max-repeats` times) and **consecutive
  tool-error streaks** (`--max-error-streak`). Accepts a file or a directory of
  fixtures, supports `--json`, and exits non-zero on failure so it can gate CI. Sample
  fixtures and usage in `docs/test/eval-fixtures/`. First slice of the v0.3.0 evaluation
  gate (Pillar 5). Enforced in CI via a "Trajectory eval gate" step that runs the
  passing fixtures in `docs/test/eval-fixtures/` (negative examples live in
  `docs/test/eval-fixtures/negative/`).
- `microclaw skill audit` subcommand — a deterministic, read-only curation view over the
  local skill corpus (no LLM, no DB, no mutation). `skill_review` distills a skill from a
  single session and the reflector retires skills purely by inactivity age; neither gives a
  cross-skill picture. The audit surfaces the signals a curator needs: **near-duplicate**
  skills (token-Jaccard over name + description — merge candidates, and a retire signal when
  an `agent-created` skill shadows a built-in), **stale** `agent-created` skills (old/absent
  `updated_at`), **thin** `agent-created` skills (near-empty body), and **cap headroom**
  against the `agent-created` ceiling. Built-in/human-curated skills are never flagged for
  retirement (they stay immutable) but still participate in duplicate detection. Accepts an
  optional directory argument (defaults to the configured skills dir), supports `--json`,
  and `--strict` exits non-zero when anything actionable is found, so it can gate CI. First
  slice of the v0.3.0 skill curator (Pillar 2).

## 0.2.0 - 2026-06-01

Milestone release consolidating everything since the 0.1.12 maturity-hardening
baseline: a concurrent specialist team, humanlike behavior, graph-augmented
memory, mid-turn interactivity, a multimedia tool suite, more channels, and
hardened packaging/release automation.

#### Agent capabilities

- Concurrent specialist team with 30 factory-ready skills and a more human
  conversational style (#391); specialist-to-specialist collaboration via the
  `consult_specialist` tool (#394)
- Humanlike follow-ups — progress-reports toggle, relationship familiarity, and
  task ETA (#392); bounded research-hard traits: humor timing, per-user growth,
  and group interjection (#393)
- Graph-augmented memory recall over the temporal knowledge graph (#395); broader
  memory & skill optimizations inspired by hermes-agent (#329)
- Concurrent mode — per-chat turn serialization with parallel tool execution
  (#320) and a chat-abort method to interrupt in-flight turns (#318)
- Mid-turn message injection for interactive agent turns (#330), with a
  real-time injection acknowledgement on non-web channels (#345)
- ACP-backed external subagent runtime (#283)

#### Tools

- `session_search` tool backed by a new SQLite FTS5 index over messages, for cross-conversation recall (schema migration v21, ported from hermes-agent's `session_search_tool.py`). Scoped to the caller's chat by default; cross-chat access goes through `authorize_chat_access` and the new `all_chats: true` opt-in is gated to control chats.
- `osv_check` tool that queries the OSV.dev advisory database for package vulnerabilities across npm, PyPI, crates.io, RubyGems, Maven, NuGet, Packagist, Hex, Pub, and Go (ported from hermes-agent's `osv_check.py`)
- `clarify` tool that sends a structured multi-choice or open-ended question through the caller's channel and releases the turn so the next user message naturally supplies the answer (ported from hermes-agent's `clarify_tool.py`)
- SSRF pre-flight checks on `web_fetch` that block requests pointing at loopback, link-local, private, CGNAT, unique-local IPv6, and cloud-metadata addresses (new `block_private_ips` field on `web_fetch_url_validation`, on by default; ported from hermes-agent's `url_safety.py`)
- Six further hermes-agent ports: prompt caching, fuzzy edit, guardrails, checkpoints, `@`-references, and subdir hints (#342)
- Multimedia tool suite (OpenAI-compatible, disabled by default, opt-in per tool via `media.<tool>.enabled`):
  - `generate_image` — POST `/v1/images/generations`; saves PNG under `<data_dir>/media/images/` and delivers via channel attachment when supported
  - `describe_image` — POST `/v1/chat/completions` with an image content block; accepts file paths (inside working_dir), URLs, or `data:` URIs
  - `text_to_speech` — POST `/v1/audio/speech`; saves MP3/OGG/etc. under `<data_dir>/media/audio/` and delivers via channel attachment
  - `transcribe_audio` — POST `/v1/audio/transcriptions` (multipart); exposes Whisper-style STT as an agent tool
  - Shared `MediaClient` enforces SSRF guard on the configured base URL, redacts API keys from `Debug`, and resolves credentials from (in order) `media.api_key`, `MICROCLAW_OPENAI_API_KEY`, `OPENAI_API_KEY`, or the existing top-level `openai_api_key`

#### Skills

- `propagation-trace` built-in skill (#384)
- Improved skill scores for microclaw (#279)
- Automated skill review CI for `SKILL.md` pull requests (#311)

#### Channels

- Telegram reply-chain support (#383)
- Native WeChat/Weixin (openclaw-weixin) support (#289) with markdown rendering in outbound messages (#324)
- Feishu/Lark ACK reaction (已读标记), opt-in with simplified emoji selection (#290)
- Mission Control gateway/session bridge and web auth UI improvements (#273, #278)

#### Packaging & release

- Official container image release automation for GHCR, with optional Docker Hub mirroring when repository credentials are configured (#277)
- Windows installer and gateway service support (#269)
- Snap package for Ubuntu and other snap-enabled distros (#325)
- `--full` / `-Full` flag across installer and Homebrew tap for heavy integrations
- Governance documents for security reporting, contribution expectations, and operator support
- CI coverage and dependency-audit gates; release packaging coverage for macOS artifacts and checksum publication
- Stronger config self-check coverage for risky execution settings

### Changed

- Replaced the homepage's external architecture image with a responsive, theme-aware native diagram.
- Refined the documentation site's mobile navigation, typography, and neutral-first visual palette for clearer small-screen browsing.
- Heavy integrations are now optional build features; MCP returned to the default build, with `full` reserved for Matrix only (#313)
- Reduced release artifact size via release-profile tuning (#310)
- Raised the default web inflight limit to 10
- CI now builds the website docs alongside the web UI
- Docker builds now compile embedded web assets inside the image build and default the runtime image to `microclaw start`
- Release process documentation now points to explicit support and release-policy artifacts

### Fixed

- UTF-8-safe string slicing in `memory_backend.rs` and `web.rs` (#381)
- `install.ps1` renames the `$pid` parameter to avoid a PowerShell read-only variable (#344)
- Nix builds derive web npm deps from the lockfile via `importNpmLock` (#333)
- Config updates preserve YAML comments (#332)
- rustls websocket provider panic (#316) and restored websocket session compatibility (#298, #300)
- Normalized malformed OpenAI tool arguments (#304)
- Reflector strips thinking/variant tags from message content before LLM processing (#303)
- Runtime config loading and invalid-model fallback (#301)
- Feishu attachments, MiniMax tool calls, and scheduler retries (#299); WeChat PDF downloads (#302)

## 0.1.12

- Current release baseline before the maturity-hardening PR
