---
id: code-usage
title: Using MicroClaw Code
sidebar_label: Using mccode
---

# Using MicroClaw Code

This page covers the day-to-day use of `mccode`: the terminal interface,
permission modes and approvals, the shell sandbox, project trust,
verification, sessions, scripting and evaluation. Install and first steps
are in [Overview and install](./code).

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

## Interactive programs

The agent can drive REPLs and debuggers: it starts one with `bash`
`run_in_background`, sends input with `bash_input` and reads output with
`bash_output`. Input goes to stdin without a terminal, so line-oriented modes
work best (`python3 -u -i`, `node -i`, `gdb -q`). Background processes are
stopped when the session ends.

## Scripting and CI

```sh
mccode -p "update the changelog for the new flag" --mode auto --trust
mccode -p "explain the build" --json > events.jsonl
mccode review "error handling" > review.md
```

- `-p` prints the final answer (or, with `--json`, one runtime event per
  line) and exits with `0` done, `1` failed / cancelled / checks still
  failing, `2` approval pending.
- `--trust` trusts the project for this run so its checks execute; without
  it an untrusted project runs no checks.
- `--no-verify` skips checks, `--no-network` turns off network access for
  shell commands, `--sandbox off` disables the OS sandbox.

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

## See also

- [Editors and other agents](./code-editors)
- [Run tasks on a MicroClaw Server](./code-remote)
- [The MicroClaw Code proposal](https://github.com/microclaw/microclaw/blob/main/docs/roadmap/microclaw-code-proposal-cn.md)
