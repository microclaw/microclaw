#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/microclaw-release-assets.XXXXXX")"
trap 'rm -rf "$fixture_dir"' EXIT

tag="v9.8.7"
version="${tag#v}"
assets=(
  "microclaw-${version}-aarch64-apple-darwin.tar.gz"
  "microclaw-${version}-aarch64-linux-gnu.tar.gz"
  "microclaw-${version}-x86_64-apple-darwin.tar.gz"
  "microclaw-${version}-x86_64-linux-gnu.tar.gz"
  "microclaw-${version}-x86_64-windows-msvc.zip"
  "microclaw-full-${version}-aarch64-apple-darwin.tar.gz"
  "microclaw-full-${version}-aarch64-linux-gnu.tar.gz"
  "microclaw-full-${version}-x86_64-apple-darwin.tar.gz"
  "microclaw-full-${version}-x86_64-linux-gnu.tar.gz"
  "microclaw-full-${version}-x86_64-windows-msvc.zip"
  "microclaw-work-${version}-aarch64-linux-gnu.tar.gz"
  "microclaw-work-${version}-x86_64-linux-gnu.tar.gz"
  "microclaw-work-${version}-x86_64-windows-msvc.zip"
  "reliability-scorecard-${tag}.json"
  "reliability-scorecard-${tag}.md"
)

for asset in "${assets[@]}"; do
  touch "${fixture_dir}/${asset}"
done

"${repo_root}/scripts/ci/check_release_assets.sh" "$fixture_dir" "$tag"

rm "${fixture_dir}/${assets[0]}"
if "${repo_root}/scripts/ci/check_release_assets.sh" "$fixture_dir" "$tag" >/dev/null 2>&1; then
  echo "missing artifact was incorrectly accepted" >&2
  exit 1
fi
touch "${fixture_dir}/${assets[0]}"

touch "${fixture_dir}/internal.dockerbuild"
if "${repo_root}/scripts/ci/check_release_assets.sh" "$fixture_dir" "$tag" >/dev/null 2>&1; then
  echo "unexpected artifact was incorrectly accepted" >&2
  exit 1
fi

echo "release artifact manifest tests passed"
