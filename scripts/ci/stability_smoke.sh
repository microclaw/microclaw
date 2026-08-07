#!/usr/bin/env bash
set -euo pipefail

echo "[stability-smoke] reliability proof pack"
if [[ -n "${RELIABILITY_SCORECARD_DIR:-}" ]]; then
  scripts/ci/reliability_scorecard.sh --output-dir "$RELIABILITY_SCORECARD_DIR"
else
  scripts/ci/reliability_scorecard.sh
fi

echo "[stability-smoke] sandbox fallback behavior"
cargo test --quiet -p microclaw-tools test_router_falls_back_to_host_when_runtime_missing_and_not_required

echo "[stability-smoke] web inflight behavior"
cargo test --quiet test_same_session_concurrency_limited

echo "[stability-smoke] completed"
