# MicroClaw Code (`mccode`)

MicroClaw Code is a coding agent for your repository. It opens the repository
that contains the current directory and runs the MicroClaw Agent Engine in it.
Use it in [Zed](https://zed.dev)'s Agent Panel (recommended, through `mccode
acp`), in a full-screen TUI, or with `-p` for one non-interactive task.
It reaches the engine only through the public `microclaw-sdk`; turn logic
(approvals, verification, fix rounds) lives in `crates/microclaw-code-core`.

Status: **Preview**.

## Install and configure

```sh
curl -fsSL https://microclaw.org/install-mccode.sh | bash   # macOS, Linux
# Windows: iwr https://microclaw.org/install-mccode.ps1 -UseBasicParsing | iex
# or: brew install microclaw/tap/mccode, or from source:
#     cargo install --git https://github.com/microclaw/microclaw microclaw-code
mccode setup                               # choose a provider, model and key
cd path/to/your/repo
mccode
mccode update                              # later: install the latest release (checksum-verified)
```

To use it in Zed (free for macOS, Linux and Windows:
[download](https://zed.dev/download), `brew install --cask zed`,
`curl -f https://zed.dev/install.sh | sh` or
`winget install -e --id ZedIndustries.Zed`), add it to Zed's settings
(`zed: open settings`) with the path from `which mccode`, then choose
**MicroClaw Code** in the Agent Panel (needs `mccode` 0.27.0 or later):

```json
{
  "agent_servers": {
    "MicroClaw Code": { "type": "custom", "command": "/path/to/mccode", "args": ["acp"] }
  }
}
```

The [Zed guide](https://microclaw.org/docs/code-editors) covers modes,
approvals, trust and troubleshooting.

`mccode setup` writes `~/.mccode/config.yaml`; a model profile in
`~/.mccode/settings.yaml` works too. Otherwise pass `--config <PATH>` or set
`MCCODE_CONFIG`. A `microclaw.config.yaml` inside the repository is never
loaded, so a cloned project cannot choose the model endpoint or tool policy.

All Code state lives in `~/.mccode` (override with `MCCODE_HOME`): the model
configuration, the engine database, memory and checkpoints (`data/`), the
session index and trust decisions.

MicroClaw Code and the MicroClaw Server are separate products. Each installs,
updates and uninstalls on its own, and neither reads the other's
configuration, data or `MICROCLAW_*` / `MCCODE_*` variables; they share no
model settings. Pairing with a Server (`mccode remote pair`) is the only link,
and only when you set it up.

## Use

```sh
mccode                                   # full-screen interface
mccode "fix the failing parser test"     # start with a task
mccode -c                                # continue the most recent session here (shows its history)
mccode --session <id>                    # resume a session (see `mccode sessions`)
mccode -p "add a --verbose flag" --mode auto   # one task, then exit
mccode -p "explain the build" --json            # JSON Lines runtime events
microclaw code …                         # same, through the Server binary
```

In the TUI (all keys can be rebound in `tui.keymap`; `/keys` lists them):

| Key | Action |
|---|---|
| Enter | send; while the agent works, queue the message for the next turn |
| Ctrl+S | while the agent works: send now, as guidance for the running turn |
| Alt+Enter, Shift+Enter, Ctrl+J | new line |
| Shift+Tab | cycle mode: plan → ask → auto |
| `/`, `@` | fuzzy pop-ups for commands and files (Tab or Enter accepts) |
| Ctrl+P | command palette |
| Up / Ctrl+R | input history / search it (kept per project) |
| Ctrl+G | edit the prompt in `$EDITOR` |
| `!` at the start | run a shell command yourself; its output goes into the next prompt |
| Ctrl+V | attach an image from the clipboard |
| Ctrl+T | the whole transcript, with search |
| Ctrl+O, click | expand / collapse all tool output (or click one) |
| Esc Esc | pick an earlier turn to rewind the files to |
| F2 | review changes hunk by hunk: revert one, or comment and send the comments as a prompt |
| Ctrl+B | show or hide the side panel (plan, checks, changes, sub-agents) |
| Esc / Ctrl+C | stop the running agent |
| Ctrl+C twice, Ctrl+D, `/exit` | quit |

Commands: `/help`, `/mode [plan|ask|auto]`, `/plan [task]`, `/check [name|all]`,
`/verify [on|off]`, `/trust`, `/allow`, `/diff [full]`, `/new`, `/sessions`, `/status`,
`/init`, `/clear`, `/exit`, and:

| Command | What it does |
|---|---|
| `/undo` | Restore the files to how they were before the last turn that changed them. The state you leave is checkpointed too. |
| `/rewind [id]` | Pick an earlier turn of this session to restore the files to, or restore checkpoint `id`. |
| `/review [focus]` | Review the uncommitted changes (`git diff HEAD` plus untracked files) with read-only tools and report findings by severity. Also `mccode review [focus]` for scripts. |
| `/model [name\|reset]` | Show or switch the model for this session (a picker without a name). |
| `/cost` | Requests and input/output tokens of this session, per model. |
| `/compact [focus]` | Summarize older messages now; the optional focus says what the summary must keep. |
| `/context` | How full the context window is: tokens used, the automatic-compaction point, and where the tokens go. |
| `/handoff <next task>` | Start a new session from a summary of this one focused on the next task. |
| `/fork` | Continue in a copy of the conversation; the original session is kept. |
| `/goal <condition>` | Keep working, turn after turn, until the condition holds and the checks pass. |
| `/btw <question>` | Ask a side question in a copy of the session; the main conversation is not changed. |
| `/changes` | Review the changes (same as F2). |
| `/theme [name]` | Pick a theme, with a live preview. |
| `/config`, `/permissions`, `/hooks` | Show the effective settings, permission rules and hooks, and where each comes from. |
| `/configure <request>` | Describe a settings change in plain words; the model proposes it and you confirm before anything is written. |
| `/queue`, `/keys`, `/import` | Queued messages, key bindings, importing Claude Code / Codex / OpenCode settings. |

Each turn ends with a receipt: changed files, check results, sandbox and
network use, tokens (and cost when the model's price is known) and the
checkpoint to rewind to.

Also: custom commands from `.microclaw/commands/*.md` and `~/.mccode/commands/*.md`, project memory in `.microclaw/memory.md`, project helper agents in `.microclaw/agents/*.md` for the `explore` tool, language-server diagnostics after edits, and `hooks` (`after_edit`, `after_turn`) in the project file; see the [usage guide](https://microclaw.org/docs/code-usage).

## Settings, permission rules and hooks

Settings are YAML in four layers, later ones winning: user
(`~/.mccode/settings.yaml`), project (`.microclaw/settings.yaml`,
shared), local (`.microclaw/settings.local.yaml`, kept out of git) and
managed (set by an administrator). They hold the model and provider profiles
(a profile can replace the configuration file), per-role models, permission
rules, hooks, sandbox and network options, the theme and other TUI options,
and chat notifications. `mccode config show|get|set|unset|paths|doctor|init|schema|edit|migrate`
manages them, and `mccode import claude|codex|opencode` brings settings over
from other agents.

Permission rules are `allow`, `ask` and `deny` lists of `bash(...)`,
`read(...)`, `edit(...)`, `net(...)`, `mcp(...)`, `agent(...)` and `tool(...)`
patterns. Deny wins over ask, ask over allow, and an `ask` rule needs a person
even in auto mode. Hooks follow the Claude Code protocol (JSON on stdin, exit
code 2 blocks, `permissionDecision`, `updatedInput`, `additionalContext`), so
existing hook scripts work unchanged. Rules and hooks are enforced inside the
engine, so sub-agents cannot get around them. See the
[settings guide](https://microclaw.org/docs/code-settings).

With a paired MicroClaw Server, approvals and "done" notifications can be sent
to Telegram, Discord or Slack (with buttons) or Feishu while you are away from
the terminal (`notify.chat`).

Checkpoints are taken at the start of every turn in a shadow git repository
inside the Code home (`data/checkpoints`); they never touch your own `.git`.

## Shell sandbox

Shell commands (`bash`, including background processes) run in the operating
system's sandbox by default: **bubblewrap** on Linux and **Seatbelt**
(`sandbox-exec`) on macOS.

- They can read the machine, except credential directories (`~/.ssh`,
  `~/.gnupg`, `~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.kube`,
  `~/.docker`, `~/.netrc`, `~/.git-credentials`, `~/.microclaw`, `~/.mccode`).
- They can write only the repository, the temp directory and common tool
  caches (`~/.cache`, `~/.cargo`, `~/.rustup`, `~/.npm`, `~/.gradle`, `~/go`, …),
  so builds and tests keep working.
- Network access is on; `--no-network` turns it off. With network off, a
  command in the sandbox cannot change anything outside the repository, so in
  `ask` mode such commands run **without asking** (destructive ones such as
  `git push` or `rm -rf` still ask).
- On Linux without a working `bwrap`, **Landlock** is used instead: writes are
  confined the same way (and outgoing TCP is blocked on kernels with Landlock
  ABI 4+), but credential directories stay readable, so commands keep asking.
  `MCCODE_LOCAL_SANDBOX=landlock` forces Landlock and `MCCODE_LOCAL_SANDBOX=none`
  turns the OS sandbox off; any other value (or none) detects the best one.

`--review-commands` has the model annotate every approval with a one-line
verdict; a command it calls `DANGEROUS` asks you even in `auto` mode.

This is defence in depth: the approval rules above still apply. Turn it off
with `--sandbox off` (or `MCCODE_SANDBOX=off`). If the machine has no
working OS sandbox (no `bwrap`, or unprivileged user namespaces disabled),
Code says so at startup and commands run unsandboxed; `mccode doctor` reports
the state. The MicroClaw Server can use the same mechanism with
`sandbox: { mode: all, backend: local }`.

## Permission modes

| Mode | Behaviour |
|---|---|
| `plan` | Read-only tools; the agent proposes a plan. Approve it to switch to `ask` and execute. |
| `ask` (default) | File edits apply directly (shown as diffs, with checkpoints); shell commands ask first. |
| `auto` | Shell commands run without asking, except destructive ones (`rm -rf`, `git push`, `git reset --hard`, `sudo`, `curl … \| sh`, `publish`, plus your `always_ask` patterns). |

Outside plan mode the agent gets the workspace tool set
(`ToolPolicy::WorkspaceWrite`): file, search, shell, planning, sub-agent and
MCP tools, without channel delivery, scheduling, A2A or media tools.

In the TUI an approval pauses the agent in place: the dialog's answer goes
back into the same run (approve once, always allow the tool in this session,
deny — the agent sees the denial and continues). For shell commands it also
offers **always allow `<command prefix>` in this project** (key `p`), for
example `cargo test`. Such a rule covers only single simple commands that
start with the prefix (`cargo test -p x`, but never `cargo test && …`, pipes,
redirections or `$(…)`); interpreters, `sudo`, `rm`, `curl` and the like
cannot be allowed by prefix, and the destructive list above still asks.
Rules live in `~/.mccode/allow-rules.json`; manage them with
`/allow [list | add <prefix> | rm <prefix>]` or `mccode allow [list | add | remove]`.

In `-p` mode an approval that needs a person ends the run with exit code 2;
resume it with `mccode --session <id> -p 1` (approve once) or `-p 3` (deny).
Exit codes: `0` done, `1` failed / cancelled / checks still failing, `2`
approval pending.

## Project trust

`.microclaw/project.yaml` lives in the repository and can set the mode, add
instructions and define check commands, so it only takes effect once you
trust the project — for the exact file content you trusted. If the file
changes later (for example after a pull), Code asks again. The TUI asks on
first use; in `-p` mode pass `--trust`; change the decision with
`mccode trust [--revoke]` or `/trust`. Untrusted projects ignore the file and
never run checks automatically (checks execute the repository's own build
scripts).

Trusted projects also load the repository's `AGENTS.md` (or `CLAUDE.md`,
`AGENT.md`; the first one found, up to 16 KB) into the agent's instructions.
In an untrusted project the agent is only told that the file exists.

## Verification

Checks are detected for Rust, Node (npm/pnpm/yarn/bun scripts), Python
(ruff/pytest/mypy), Go and Makefiles, or configured in
`.microclaw/project.yaml`. In trusted projects, when a turn changed the
working tree — through the file tools or through shell commands — the `auto`
checks run; a failure goes back to the agent (up to `max_fix_rounds`,
default 2) with an explicit instruction not to weaken tests.

```sh
mccode info          # detected project, trust, checks, config sources
mccode check         # run all checks
mccode check build   # run one
mccode init          # write .microclaw/project.yaml
mccode doctor        # validate the configuration and start the engine once
```

`.microclaw/project.yaml`:

```yaml
mode: ask
verify: true
max_fix_rounds: 2
checks:
  - name: build
    run: cargo check --all-targets
    auto: true
  - name: test
    run: cargo test
always_ask:
  - terraform apply
instructions: |
  Use pnpm, not npm.
compact_instructions: Keep the names of public APIs and any open TODOs.
```

## Editors, other agents and remote Servers

| Command | What it does |
|---|---|
| `mccode acp` | Agent Client Protocol on stdio, for editors such as Zed (add a custom agent with command `mccode` and argument `acp`). Sessions map to MicroClaw Code sessions in the project of their `cwd`; approvals become permission requests; modes are plan / ask / auto; `session/load` replays history. |
| `mccode mcp-server` | Model Context Protocol server on stdio with tools `run` (a task, with verification and fix rounds; approvals end the call and are answered by calling `run` again with the session and `1`/`2`/`3`) and `review`. |
| `mccode remote pair <url> <code>` | Pair with a MicroClaw Server using a code from its web console (Access tab); `remote status`, `remote forget`. |
| `mccode -p "…" --remote` | Run the task on the paired Server (its working directory, tools and approval policy), streaming the result here. Approvals: exit 2, then `--remote --session <key> -p 1\|3`. |

Flags such as `--mode`, `--sandbox`, `--no-network` and `--no-verify` go
before the subcommand (`mccode --mode auto acp`). Only projects you already
trusted (TUI, `mccode trust`) honour `.microclaw/project.yaml` here.

Step-by-step setup for Zed, Claude Code, Codex and Cursor:
[Use with Zed](https://microclaw.org/docs/code-editors).

The agent can also drive interactive programs: start a REPL or debugger with
`bash` `run_in_background`, then send it input with `bash_input` (stdin, no
terminal: use line-oriented modes such as `python3 -u -i`).

## Evaluation

```sh
mccode eval apps/microclaw-code/eval/cases            # PASS/FAIL per case
mccode --json eval my-cases --filter parser            # JSON Lines
mccode eval replay v0.10.0..HEAD --check "cargo test" --out eval/replay
```

A case is a directory with `case.yaml` (`prompt`, `check`, optional `setup`,
`mode`, `timeout_secs`, `followups` for further turns in the same session,
`context_window` to pretend the model's window is smaller, and
`min_compactions`) and a `repo/` snapshot. Each case runs in a fresh git
repository in `auto` mode with verification; the case passes when `check`
exits 0 afterwards and at least `min_compactions` compactions happened. `eval replay` turns bug-fix commits into cases (parent
commit = snapshot, commit message = prompt), a regression set built from real
history. Results include duration, requests and tokens.

## Design

See [`docs/roadmap/microclaw-code-proposal-cn.md`](../../docs/roadmap/microclaw-code-proposal-cn.md).
