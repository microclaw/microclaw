#!/usr/bin/env bash
# Tokens-per-task extraction for the published benchmark
# (docs/reports/benchmarks/tokens-per-task.md).
#
# Run each canonical task in its own fresh chat, then point this script at
# the runtime database. It reports, per chat, the total input/output tokens
# and call count within the window — the raw rows behind the published
# numbers. Nothing here estimates: it reads the same llm_usage_logs the
# `insights` tool and token budgets use.
set -euo pipefail

usage() {
  echo "Usage: $0 --db PATH [--since RFC3339] [--json]" >&2
}

db=""
since="1970-01-01T00:00:00Z"
json=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --db) [[ $# -ge 2 ]] || { usage; exit 2; }; db="$2"; shift 2 ;;
    --since) [[ $# -ge 2 ]] || { usage; exit 2; }; since="$2"; shift 2 ;;
    --json) json=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done
[[ -n "$db" ]] || { usage; exit 2; }
[[ -f "$db" ]] || { echo "Database not found: $db" >&2; exit 1; }

query="SELECT chat_id,
       COUNT(*) AS calls,
       SUM(input_tokens) AS input_tokens,
       SUM(output_tokens) AS output_tokens,
       SUM(total_tokens) AS total_tokens
  FROM llm_usage_logs
 WHERE created_at >= '$since'
 GROUP BY chat_id
 ORDER BY chat_id;"

if command -v sqlite3 >/dev/null; then
  if [[ "$json" -eq 1 ]]; then
    sqlite3 -json "$db" "$query"
  else
    echo "chat_id|calls|input_tokens|output_tokens|total_tokens"
    sqlite3 "$db" "$query"
  fi
elif command -v python3 >/dev/null; then
  # MicroClaw bundles SQLite, so hosts often lack the sqlite3 CLI; the
  # python3 stdlib driver reads the same file.
  DB="$db" QUERY="$query" JSON="$json" python3 - <<'PY'
import json as j, os, sqlite3
rows = sqlite3.connect(os.environ["DB"]).execute(os.environ["QUERY"].rstrip(";")).fetchall()
cols = ["chat_id", "calls", "input_tokens", "output_tokens", "total_tokens"]
if os.environ["JSON"] == "1":
    print(j.dumps([dict(zip(cols, r)) for r in rows], indent=2))
else:
    print("|".join(cols))
    for r in rows:
        print("|".join(str(v) for v in r))
PY
else
  echo "sqlite3 or python3 is required" >&2
  exit 1
fi
