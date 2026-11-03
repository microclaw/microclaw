# MicroClaw Code (`mccode`)

MicroClaw Code is a terminal coding agent. It opens the repository that
contains the current directory and runs the MicroClaw Agent Engine in it: a
full-screen TUI for interactive work, or `-p` for one non-interactive task.
It reaches the engine only through the public `microclaw-sdk`; turn logic
(approvals, verification, fix rounds) lives in `crates/microclaw-code-core`.

Status: **Preview**.

## Install and configure

```sh
cargo install --path apps/microclaw-code   # installs `mccode`
mccode setup                               # choose a provider, model and key
cd path/to/your/repo
mccode
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
mccode -c                                # continue the most recent session here
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
`/verify [on|off]`, `/trust`, `/diff [full]`, `/new`, `/sessions`, `/status`,
`/init`, `/clear`, `/exit`.

## Permission modes

| Mode | Behaviour |
|---|---|
| `plan` | Read-only tools; the agent proposes a plan. Approve it to switch to `ask` and execute. |
| `ask` (default) | File edits apply directly (shown as diffs, with checkpoints); shell commands ask first. |
| `auto` | Shell commands run without asking, except destructive ones (`rm -rf`, `git push`, `git reset --hard`, `sudo`, `curl … \| sh`, `publish`, plus your `always_ask` patterns). |

Outside plan mode the agent gets the workspace tool set
(`ToolPolicy::WorkspaceWrite`): file, search, shell, planning, sub-agent and
MCP tools, without channel delivery, scheduling, A2A or media tools.

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

## Design

See [`docs/roadmap/microclaw-code-proposal-cn.md`](../../docs/roadmap/microclaw-code-proposal-cn.md).
