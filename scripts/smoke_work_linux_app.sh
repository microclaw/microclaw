#!/usr/bin/env bash
set -euo pipefail

work_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work_repo_root="$(cd "$work_script_dir/.." && pwd)"
work_profile="${1:-release}"
work_binary="$work_repo_root/target/$work_profile/microclaw-work"
work_log="$work_repo_root/target/$work_profile/microclaw-work-linux-launch-smoke.log"

case "$work_profile" in
  debug|release) ;;
  *)
    echo "usage: $0 [debug|release]" >&2
    exit 2
    ;;
esac

if [[ ! -x "$work_binary" ]]; then
  echo "expected MicroClaw Work executable not found: $work_binary" >&2
  exit 1
fi

"$work_binary" >"$work_log" 2>&1 &
work_pid=$!

for _ in 1 2 3 4 5 6; do
  if ! kill -0 "$work_pid" 2>/dev/null; then
    wait "$work_pid" || true
    sed -n '1,160p' "$work_log" >&2
    echo "MicroClaw Work exited during Linux launch smoke" >&2
    exit 1
  fi
  sleep 0.5
done

kill "$work_pid"
wait "$work_pid" 2>/dev/null || true
echo "MicroClaw Work Linux launch smoke passed (pid $work_pid)"
