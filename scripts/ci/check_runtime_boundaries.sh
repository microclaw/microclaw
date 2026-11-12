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

for consumer in microclaw-sdk microclaw-code-core microclaw-code; do
  consumer_tree="$(cargo tree -p "$consumer" -e normal --all-features --prefix none)"
  if printf '%s\n' "$consumer_tree" | cut -d' ' -f1 | grep -Fxq microclaw; then
    printf '%s must consume microclaw-engine and must not depend on the root product package\n' "$consumer" >&2
    exit 1
  fi
done

for consumer in microclaw-code-core microclaw-code; do
  direct_tree="$(cargo tree -p "$consumer" -e normal --depth 1 --prefix none)"
  if ! printf '%s\n' "$direct_tree" | cut -d' ' -f1 | grep -Fxq microclaw-sdk; then
    printf '%s must enter Agent execution through microclaw-sdk\n' "$consumer" >&2
    exit 1
  fi
  # MicroClaw Code reaches the Agent Engine only through the public SDK.
  if printf '%s\n' "$direct_tree" | cut -d' ' -f1 | grep -Fxq microclaw-engine; then
    printf '%s must not depend on microclaw-engine directly; extend microclaw-sdk instead\n' "$consumer" >&2
    exit 1
  fi
done

engine_direct_tree="$(cargo tree -p microclaw-engine -e normal --depth 1 --prefix none)"
for forbidden in microclaw axum teloxide serenity; do
  if printf '%s\n' "$engine_direct_tree" | cut -d' ' -f1 | grep -Fxq "$forbidden"; then
    printf 'microclaw-engine must not directly depend on product/UI package %s\n' "$forbidden" >&2
    exit 1
  fi
done

# The desktop app is a workspace of its own (GPUI); read its manifest
# without resolving GPUI so this runs on every platform.
desktop_deps="$(cargo metadata --manifest-path apps/microclaw-code-desktop/Cargo.toml \
  --no-deps --format-version 1 \
  | jq -r '.packages[] | select(.name == "microclaw-code-desktop") | .dependencies[] | select(.kind == null) | .name')"
for required in microclaw-sdk microclaw-code-core; do
  if ! printf '%s\n' "$desktop_deps" | grep -Fxq "$required"; then
    printf 'microclaw-code-desktop must reach the engine through %s\n' "$required" >&2
    exit 1
  fi
done
for forbidden in microclaw microclaw-engine; do
  if printf '%s\n' "$desktop_deps" | grep -Fxq "$forbidden"; then
    printf 'microclaw-code-desktop must not depend on %s directly; extend microclaw-sdk or microclaw-code-core instead\n' "$forbidden" >&2
    exit 1
  fi
done
