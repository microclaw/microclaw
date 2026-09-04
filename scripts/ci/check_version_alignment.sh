#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

release_version="$(cargo metadata --no-deps --format-version 1 \
  | jq -r '.packages[] | select(.name == "microclaw") | .version')"

rust_packages=(
  microclaw
  microclaw-core
  microclaw-engine
  microclaw-sdk
  microclaw-work
  microclaw-work-app
  microclaw-work-runtime
  microclaw-work-headless
)

metadata="$(cargo metadata --no-deps --format-version 1)"
for package in "${rust_packages[@]}"; do
  version="$(jq -r --arg package "$package" \
    '.packages[] | select(.name == $package) | .version' <<<"$metadata")"
  if [[ -z "$version" || "$version" == "null" ]]; then
    echo "missing release package: $package" >&2
    exit 1
  fi
  if [[ "$version" != "$release_version" ]]; then
    echo "$package is $version; expected $release_version" >&2
    exit 1
  fi
done

for package_json in web/package.json site/package.json; do
  version="$(jq -r '.version' "$package_json")"
  if [[ "$version" != "$release_version" ]]; then
    echo "$package_json is $version; expected $release_version" >&2
    exit 1
  fi
done

echo "Server, Work, SDK, and UI packages are aligned at $release_version."
