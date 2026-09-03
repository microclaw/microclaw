#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

runtime_tree="$(cargo tree -p microclaw-runtime -e normal --prefix none)"
for forbidden in axum gpui teloxide serenity microclaw-channels microclaw-work-runtime; do
  if printf '%s\n' "$runtime_tree" | cut -d' ' -f1 | grep -Fxq "$forbidden"; then
    printf 'microclaw-runtime must not depend on %s\n' "$forbidden" >&2
    exit 1
  fi
done

for preset in minimal standard full; do
  cargo check -p microclaw-runtime --no-default-features --features "$preset"
  cargo check -p microclaw-sdk --no-default-features --features "$preset"
done

work_direct_tree="$(cargo tree -p microclaw-work-runtime -e normal --depth 1 --prefix none)"
if printf '%s\n' "$work_direct_tree" | cut -d' ' -f1 | grep -Fxq microclaw; then
  printf 'microclaw-work-runtime must consume the SDK instead of depending directly on microclaw\n' >&2
  exit 1
fi
