---
id: code
title: MicroClaw Code
sidebar_position: 4
---

# MicroClaw Code (`mccode`)

MicroClaw Code is a terminal coding agent. It opens the repository that
contains the current directory and runs the MicroClaw Agent Engine in it: a
full-screen TUI for interactive work, or `-p` for one non-interactive task.
It reaches the engine only through the public `microclaw-sdk`; turn logic
(approvals, verification, fix rounds) lives in `crates/microclaw-code-core`.

Status: **Preview**.

## Install and configure

```sh
brew install microclaw/tap/mccode          # macOS (the Server is a separate formula: microclaw)
# or download mccode-<version>-<target> from the GitHub release, or
cargo install --path apps/microclaw-code   # build mccode from source
mccode setup                               # choose a provider, model and key
cd path/to/your/repo
mccode
mccode update                              # later: install the latest release (checksum-verified)
```

`mccode setup` writes `~/.microclaw/code/config.yaml`. Without it, `mccode`
borrows model credentials from `--config <PATH>`, `MICROCLAW_CODE_CONFIG`,
`MICROCLAW_CONFIG` or a MicroClaw Server `~/.microclaw/microclaw.config.yaml`.
A `microclaw.config.yaml` inside the repository is never loaded, so a cloned
project cannot choose the model endpoint or tool policy.

All Code state lives in `~/.microclaw/code` (override with
`MICROCLAW_CODE_HOME`): the engine database, memory and checkpoints
(`data/`), the session index and trust decisions. It never shares a database
or memory with a MicroClaw Server on the same machine.

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

In the TUI:

| Key | Action |
|---|---|
| Enter | send (while the agent works: guide it) |
| Alt+Enter, Ctrl+J, trailing `\` | new line |
| Shift+Tab | cycle mode: plan → ask → auto |
| Tab | complete `/commands` and `@path` file mentions |
| Esc / Ctrl+C | stop the running agent |
| Ctrl+C twice, Ctrl+D, `/exit` | quit |
| PgUp / PgDn, End | scroll the transcript |
| Up / Down | input history |

Commands: `/help`, `/mode [plan|ask|auto]`, `/plan [task]`, `/check [name|all]`,
`/verify [on|off]`, `/trust`, `/allow`, `/diff [full]`, `/new`, `/sessions`, `/status`,
`/init`, `/clear`, `/exit`, and:

| Command | What it does |
|---|---|
| `/undo` | Restore the files to how they were before the last turn that changed them. The state you leave is checkpointed too. |
| `/rewind [id]` | List workspace checkpoints, or restore one. |
| `/review [focus]` | Review the uncommitted changes (`git diff HEAD` plus untracked files) with read-only tools and report findings by severity. Also `mccode review [focus]` for scripts. |
| `/model [name\|reset]` | Show or switch the model for this session. |
| `/cost` | Requests and input/output tokens of this session, per model. |
| `/compact` | Summarize older messages now to free context (long sessions also compact automatically). |
| `/fork` | Continue in a copy of the conversation; the original session is kept. |

Checkpoints are taken at the start of every turn in a shadow git repository
inside the Code home (`data/checkpoints`); they never touch your own `.git`.

## Shell sandbox

Shell commands (`bash`, including background processes) run in the operating
system's sandbox by default: **bubblewrap** on Linux and **Seatbelt**
(`sandbox-exec`) on macOS.

- They can read the machine, except credential directories (`~/.ssh`,
  `~/.gnupg`, `~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.kube`,
  `~/.docker`, `~/.netrc`, `~/.git-credentials`, `~/.microclaw`).
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
  `MICROCLAW_LOCAL_SANDBOX=bubblewrap|landlock|none` overrides the choice.

`--review-commands` has the model annotate every approval with a one-line
verdict; a command it calls `DANGEROUS` asks you even in `auto` mode.

This is defence in depth: the approval rules above still apply. Turn it off
with `--sandbox off` (or `MICROCLAW_CODE_SANDBOX=off`). If the machine has no
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
Rules live in `~/.microclaw/code/allow-rules.json`; manage them with
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
`mode`, `timeout_secs`) and a `repo/` snapshot. Each case runs in a fresh git
repository in `auto` mode with verification; the case passes when `check`
exits 0 afterwards. `eval replay` turns bug-fix commits into cases (parent
commit = snapshot, commit message = prompt), a regression set built from real
history. Results include duration, requests and tokens.

## Design

See [the MicroClaw Code proposal](https://github.com/microclaw/microclaw/blob/main/docs/roadmap/microclaw-code-proposal-cn.md).
