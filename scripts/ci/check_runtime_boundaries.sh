#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

for preset in minimal standard full; do
  cargo test -p microclaw-sdk --no-default-features --features "$preset" --lib --examples
done

minimal_tree="$(cargo tree -p microclaw-sdk --no-default-features --features minimal -e normal --prefix none)"
for forbidden in microclaw-engine reqwest rusqlite tokio typst opentelemetry; do
  if printf '%s\n' "$minimal_tree" | cut -d' ' -f1 | grep -Fxq "$forbidden"; then
    printf 'microclaw-sdk minimal must not depend on %s\n' "$forbidden" >&2
    exit 1
  fi
done

standard_tree="$(cargo tree -p microclaw-sdk --no-default-features --features standard -e normal --prefix none)"
for forbidden in typst typst-pdf typst-layout; do
  if printf '%s\n' "$standard_tree" | cut -d' ' -f1 | grep -Fxq "$forbidden"; then
    printf 'microclaw-sdk standard must not depend on %s\n' "$forbidden" >&2
    exit 1
  fi
done

for consumer in microclaw-sdk microclaw-work-runtime microclaw-work-headless; do
  consumer_tree="$(cargo tree -p "$consumer" -e normal --all-features --prefix none)"
  if printf '%s\n' "$consumer_tree" | cut -d' ' -f1 | grep -Fxq microclaw; then
    printf '%s must consume microclaw-engine and must not depend on the root product package\n' "$consumer" >&2
    exit 1
  fi
done

for consumer in microclaw-work-runtime microclaw-work-headless; do
  direct_tree="$(cargo tree -p "$consumer" -e normal --depth 1 --prefix none)"
  if ! printf '%s\n' "$direct_tree" | cut -d' ' -f1 | grep -Fxq microclaw-sdk; then
    printf '%s must enter Agent execution through microclaw-sdk\n' "$consumer" >&2
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
