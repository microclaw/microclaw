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

# Public installation snippets must move with the release. These counts cover
# every user-facing Cargo.toml example that names microclaw-sdk directly.
sdk_doc_snippets=(
  "README.md:1"
  "README_CN.md:1"
  "site/src/pages/index.js:1"
  "site/docs/sdk-quickstart.md:1"
  "site/docs/sdk-features.md:3"
  "site/docs/sdk-workers.md:1"
  "docs/operations/rust-sdk-release.md:1"
)

for snippet in "${sdk_doc_snippets[@]}"; do
  file="${snippet%:*}"
  expected_count="${snippet##*:}"
  actual_count="$(grep -Foc "version = \"$release_version\"" "$file" || true)"
  if [[ "$actual_count" != "$expected_count" ]]; then
    echo "$file has $actual_count current SDK version snippet(s); expected $expected_count for $release_version" >&2
    exit 1
  fi
done

for file in README.md README_CN.md site/src/pages/index.js site/src/home-i18n.js site/docs/overview.md; do
  if ! grep -Fq "v$release_version" "$file"; then
    echo "$file does not identify v$release_version as the current release" >&2
    exit 1
  fi
done

echo "Server, Work, SDK, UI packages, and public release snippets are aligned at $release_version."
