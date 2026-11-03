# mcdesk — MicroClaw Desktop in your terminal

`mcdesk` is the terminal entry point of **MicroClaw Desktop**, the local
MicroClaw product. The desktop app (`apps/microclaw-work`) and `mcdesk` share
one Agent Engine (through `microclaw-sdk`), one session store and state
machine (`microclaw-work-app`), and the project, trust and verification
services in `microclaw-work-runtime`. A session started in the terminal shows
up in the desktop app, and `/desktop` hands it over.

Status: **Preview**.

## Run

```sh
cargo build --release -p microclaw-desktop-cli
cd path/to/your/repo
mcdesk                               # interactive session
mcdesk "fix the failing test in src/parser.rs"
mcdesk -p "add a --verbose flag" --mode auto      # one task, then exit
mcdesk -p "explain the build" --json              # JSON Lines events
mcdesk -c                            # continue the most recent session here
mcdesk sessions                      # this project's sessions (shared with the app)
mcdesk desktop                       # continue in the desktop app
microclaw desktop …                  # same, through the main microclaw binary
```

Model credentials: `--config <PATH>`, `MICROCLAW_WORK_CONFIG`,
`MICROCLAW_CONFIG`, the model settings saved by the desktop app, or
`~/.microclaw/microclaw.config.yaml`. A `microclaw.config.yaml` inside the
repository is never loaded, so a cloned project cannot choose the model
endpoint or tool policy.

## Project trust

`.microclaw/project.yaml` lives in the repository and can set the mode, add
instructions and define check commands, so it only takes effect once you
trust the project. `mcdesk` asks the first time you open a project
interactively; in `-p` mode pass `--trust`. Change the decision with
`mcdesk trust [--revoke]` or `/trust`. Untrusted projects ignore the project
file and never run checks automatically (checks execute the repository's own
build scripts). Decisions are stored in the Desktop data directory, not in the
repository.

## Permission modes

| Mode | Behaviour |
|---|---|
| `plan` | Read-only tools; the agent presents a plan. Interactively, approve it to switch to `ask` and execute. |
| `ask` (default) | File edits apply directly (shown as diffs, with checkpoints); shell commands ask first. |
| `auto` | Shell commands run without asking, except destructive ones (`rm -rf`, `git push`, `git reset --hard`, `sudo`, `curl … \| sh`, `publish`, plus your `always_ask` patterns). |

Outside plan mode the agent gets the workspace tool set (`ToolPolicy::WorkspaceWrite`):
file, search, shell, planning, sub-agent and MCP tools, without channel delivery,
scheduling, A2A or media tools.

In `-p` mode an approval that needs a human ends the run with exit code 2 and
leaves the session awaiting approval (the desktop app shows the approval
card). Resume with `mcdesk --session <id> -p 1` (approve) or `-p 3` (deny).

## Verification

Checks are detected for Rust, Node (npm/pnpm/yarn/bun scripts), Python
(ruff/pytest/mypy), Go and Makefiles, or configured in
`.microclaw/project.yaml`. In trusted projects, after the agent changes files
the `auto` checks run; a failure is handed back to the agent (up to
`max_fix_rounds`, default 2) with an explicit instruction not to weaken tests.

```sh
mcdesk info          # what was detected, trust state, config sources
mcdesk check         # run all checks
mcdesk check build   # run one
mcdesk init          # write .microclaw/project.yaml
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

## Interactive commands

`/mode [plan|ask|auto]`, `/plan [task]`, `/check [name|all]`, `/verify [on|off]`,
`/trust`, `/diff [full]`, `/new`, `/sessions`, `/desktop`, `/session`,
`/status`, `/init`, `/exit`. Type while the agent works to steer it; Ctrl-C
stops the current run, Ctrl-C twice at the prompt quits. A line ending in `\`
continues on the next line.

## Design

See [`docs/roadmap/microclaw-desktop-proposal-cn.md`](../../docs/roadmap/microclaw-desktop-proposal-cn.md).
