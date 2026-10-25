#!/usr/bin/env bash
# Browser smoke test for the embedded Web UI.
#
# Boots the built `microclaw` binary with a throwaway web-only config and
# drives the real embedded bundle with Playwright (Chromium): sign in, type
# into the composer, send, reload, type again. Fails on any uncaught browser
# error or console.error — the class of bug that shipped in v0.8.0–v0.10.0
# (issue #517, "Maximum update depth exceeded" on the first keystroke).
#
# Usage:
#   scripts/ci/web_e2e.sh                # uses target/debug/microclaw (builds it if missing)
#   MICROCLAW_BIN=path/to/microclaw scripts/ci/web_e2e.sh
#   scripts/ci/web_e2e.sh --no-build     # never run cargo build, fail if the binary is missing
set -euo pipefail

cd "$(dirname "$0")/../.."

build=1
for arg in "$@"; do
  case "$arg" in
    --no-build) build=0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

bin="${MICROCLAW_BIN:-target/debug/microclaw}"
if [[ ! -x "$bin" ]]; then
  if [[ "$build" == "1" && -z "${MICROCLAW_BIN:-}" ]]; then
    echo "[web-e2e] building microclaw binary (cargo build)"
    cargo build
  else
    echo "[web-e2e] microclaw binary not found at $bin" >&2
    exit 1
  fi
fi
export MICROCLAW_BIN="$(cd "$(dirname "$bin")" && pwd)/$(basename "$bin")"
echo "[web-e2e] binary: $MICROCLAW_BIN"

echo "[web-e2e] installing Playwright"
npm --prefix web/e2e ci --no-audit --no-fund
echo "[web-e2e] installing Chromium (cached under ~/.cache/ms-playwright in CI)"
npm --prefix web/e2e run install-browser

echo "[web-e2e] running browser smoke tests"
npm --prefix web/e2e test
echo "[web-e2e] completed"
