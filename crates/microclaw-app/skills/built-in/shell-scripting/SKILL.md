---
name: shell-scripting
description: "Write robust, safe bash/shell scripts and one-liners, and explain or fix existing ones. Use when users want a shell script, a command pipeline, automation glue, or ask why a bash snippet misbehaves (quoting, globbing, exit codes). Triggers on mentions of bash, shell script, .sh, command line, pipe, one-liner, cron job command, 脚本, 命令行, 管道, shell."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "No external dependencies. Works on macOS, Linux, and Windows (WSL/Git Bash)."
---

# Shell Scripting

Write scripts that fail loudly and safely, not ones that silently do the wrong thing.

## Start every script with a strict header

```bash
#!/usr/bin/env bash
set -euo pipefail   # exit on error, error on unset var, fail a pipeline if any stage fails
IFS=$'\n\t'
```

## Quoting & safety (the top source of bugs)

- Always quote expansions: `"$var"`, `"${arr[@]}"`, `"$(cmd)"` — unquoted values word-split and glob.
- Use `[[ ... ]]` over `[ ... ]` for tests; `(( ... ))` for arithmetic.
- Prefer `"$(cmd)"` over backticks. Check `mkdir -p`, `rm -rf` paths twice.
- Handle filenames with spaces/newlines: `find ... -print0 | xargs -0`, or `while IFS= read -r line`.

## Common patterns

```bash
# Args with defaults
name="${1:-world}"

# Loop over files safely
for f in ./*.log; do [[ -e "$f" ]] || continue; echo "$f"; done

# Trap cleanup on exit
tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT

# Check a command exists
command -v jq >/dev/null 2>&1 || { echo "jq required" >&2; exit 1; }
```

## Guidance

- Run `shellcheck script.sh` if available — it catches most real bugs.
- Make scripts idempotent where possible; print what they're doing.
- Don't parse `ls` output; glob or use `find`. Don't `eval` untrusted input.
- For anything beyond ~50 lines of logic, consider Python instead.
