#!/usr/bin/env bash
set -euo pipefail

echo "[nightly-stability] stability smoke suite"
scripts/ci/stability_smoke.sh

echo "[nightly-stability] metrics contract assertions"
cargo test --quiet test_metrics_endpoints_return_data

echo "[nightly-stability] completed"
