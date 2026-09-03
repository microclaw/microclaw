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
  cargo test -p microclaw-runtime --no-default-features --features "$preset" --lib
  cargo test -p microclaw-sdk --no-default-features --features "$preset" --lib --examples
done

for consumer in microclaw-sdk microclaw-work-runtime; do
  consumer_tree="$(cargo tree -p "$consumer" -e normal --all-features --prefix none)"
  if printf '%s\n' "$consumer_tree" | cut -d' ' -f1 | grep -Fxq microclaw; then
    printf '%s must consume microclaw-engine and must not depend on the root product package\n' "$consumer" >&2
    exit 1
  fi
done

engine_direct_tree="$(cargo tree -p microclaw-engine -e normal --depth 1 --prefix none)"
for forbidden in microclaw axum gpui teloxide serenity; do
  if printf '%s\n' "$engine_direct_tree" | cut -d' ' -f1 | grep -Fxq "$forbidden"; then
    printf 'microclaw-engine must not directly depend on product/UI package %s\n' "$forbidden" >&2
    exit 1
  fi
done
