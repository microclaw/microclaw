#!/usr/bin/env bash
set -euo pipefail

work_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work_repo_root="$(cd "$work_script_dir/.." && pwd)"
work_profile="${1:-debug}"
work_bundle="$work_repo_root/target/microclaw-desktop-app/$work_profile/MicroClaw Desktop.app"
work_binary="$work_bundle/Contents/MacOS/microclaw-desktop"
work_log="$work_repo_root/target/microclaw-desktop-app/$work_profile/launch-smoke.log"

if [[ ! -x "$work_binary" ]]; then
  echo "expected packaged executable not found: $work_binary" >&2
  exit 1
fi

"$work_binary" >"$work_log" 2>&1 &
work_pid=$!

for _ in 1 2 3 4 5 6; do
  if ! kill -0 "$work_pid" 2>/dev/null; then
    wait "$work_pid" || true
    sed -n '1,160p' "$work_log" >&2
    echo "MicroClaw Desktop exited during launch smoke" >&2
    exit 1
  fi
  sleep 0.5
done

kill "$work_pid"
wait "$work_pid" 2>/dev/null || true
echo "MicroClaw Desktop launch smoke passed (pid $work_pid)"
