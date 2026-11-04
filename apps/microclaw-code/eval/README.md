# MicroClaw Code evaluation cases

Each directory with a `case.yaml` is one task: `repo/` is the starting
snapshot, `prompt` is what the agent is asked, and `check` must exit 0 after
the run for the case to pass.

```sh
mccode eval apps/microclaw-code/eval/cases          # run them
mccode eval apps/microclaw-code/eval/cases --json   # JSON Lines results
mccode eval replay v0.10.0..HEAD --check "cargo test" --out eval/replay
```

`eval replay` turns bug-fix commits of the current repository into cases
(parent commit = snapshot, commit message = prompt), a regression set built
from real history.
