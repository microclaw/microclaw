# MicroClaw Code

MicroClaw Code is a local, terminal-first coding agent. It opens the repository
that contains the current directory and runs the MicroClaw Agent Engine in it
through the public `microclaw-sdk` facade. It does not start channels, the Web
UI, or background schedulers.

Status: **Preview**.

## Run

```sh
cargo build --release -p microclaw-code
cd path/to/your/repo
microclaw-code                      # interactive session
microclaw-code "fix the failing test in src/parser.rs"
microclaw-code -p "add a --verbose flag" --mode auto     # one task, then exit
microclaw-code -p "explain the build" --json             # JSON Lines events
microclaw-code -c                   # continue the last session for this repo
microclaw code …                    # same, through the main microclaw binary
```

Model credentials come from your MicroClaw configuration: `--config <PATH>`,
`MICROCLAW_CODE_CONFIG`, `MICROCLAW_CONFIG`, or
`~/.microclaw/microclaw.config.yaml`. A `microclaw.config.yaml` inside the
repository is never loaded implicitly, so a cloned project cannot choose the
model endpoint or tool policy.

## Permission modes

| Mode | Behaviour |
|---|---|
| `plan` | Read-only tools; the agent presents a plan. Interactively, approve it to switch to `ask` and execute. |
| `ask` (default) | File edits apply directly (shown as diffs, with checkpoints); shell commands ask first. |
| `auto` | Shell commands run without asking, except destructive ones (`rm -rf`, `git push`, `git reset --hard`, `sudo`, `curl … \| sh`, `publish`, plus your `always_ask` patterns). |

Outside plan mode the agent gets the workspace tool set (`ToolPolicy::WorkspaceWrite`):
file, search, shell, planning, sub-agent and MCP tools, without channel delivery,
scheduling, A2A or media tools.

In `-p` mode an approval that needs a human ends the run with exit code 2;
resume it with `microclaw-code --session <name> -p 1` (approve) or `-p 3` (deny).

## Verification

MicroClaw Code detects checks for Rust, Node (npm/pnpm/yarn/bun scripts),
Python (ruff/pytest/mypy), Go and Makefiles. After the agent changes files it
runs the `auto` checks; a failure is handed back to the agent (up to
`max_fix_rounds`, default 2) with an explicit instruction not to weaken tests.

```sh
microclaw-code info          # what was detected
microclaw-code check         # run all checks
microclaw-code check build   # run one
microclaw-code init          # write .microclaw/code.yaml
```

`.microclaw/code.yaml`:

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
`/diff [full]`, `/new`, `/session`, `/status`, `/init`, `/exit`.
Type while the agent works to steer it; Ctrl-C stops the current run, Ctrl-C
twice at the prompt quits. A line ending in `\` continues on the next line.

## Design

See [`docs/roadmap/microclaw-code-proposal-cn.md`](../../docs/roadmap/microclaw-code-proposal-cn.md).
