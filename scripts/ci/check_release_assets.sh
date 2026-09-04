#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  echo "usage: $0 <artifact-directory> <release-tag>" >&2
  exit 2
fi

artifact_dir="$1"
release_tag="$2"

if [[ ! -d "$artifact_dir" ]]; then
  echo "artifact directory does not exist: $artifact_dir" >&2
  exit 1
fi

if [[ ! "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid release tag: $release_tag" >&2
  exit 1
fi

release_version="${release_tag#v}"
expected=(
  "microclaw-${release_version}-aarch64-apple-darwin.tar.gz"
  "microclaw-${release_version}-aarch64-linux-gnu.tar.gz"
  "microclaw-${release_version}-x86_64-apple-darwin.tar.gz"
  "microclaw-${release_version}-x86_64-linux-gnu.tar.gz"
  "microclaw-${release_version}-x86_64-windows-msvc.zip"
  "microclaw-full-${release_version}-aarch64-apple-darwin.tar.gz"
  "microclaw-full-${release_version}-aarch64-linux-gnu.tar.gz"
  "microclaw-full-${release_version}-x86_64-apple-darwin.tar.gz"
  "microclaw-full-${release_version}-x86_64-linux-gnu.tar.gz"
  "microclaw-full-${release_version}-x86_64-windows-msvc.zip"
  "microclaw-work-${release_version}-aarch64-linux-gnu.tar.gz"
  "microclaw-work-${release_version}-x86_64-linux-gnu.tar.gz"
  "microclaw-work-${release_version}-x86_64-windows-msvc.zip"
  "reliability-scorecard-${release_tag}.json"
  "reliability-scorecard-${release_tag}.md"
)

missing=0
for asset in "${expected[@]}"; do
  if [[ ! -f "${artifact_dir}/${asset}" ]]; then
    echo "missing release artifact: ${asset}" >&2
    missing=1
  fi
done

unexpected=0
while IFS= read -r asset; do
  allowed=0
  for expected_asset in "${expected[@]}"; do
    if [[ "$asset" == "$expected_asset" ]]; then
      allowed=1
      break
    fi
  done

  # A signed/notarized Apple Silicon Work DMG can be uploaded separately and
  # folded into the release when it exists.
  if [[ "$asset" == "microclaw-work-${release_version}-arm64-macos.dmg" ]]; then
    allowed=1
  fi

  if [[ "$allowed" -ne 1 ]]; then
    echo "unexpected release artifact: ${asset}" >&2
    unexpected=1
  fi
done < <(find "$artifact_dir" -mindepth 1 -maxdepth 1 -type f -exec basename {} \; | sort)

if [[ "$missing" -ne 0 || "$unexpected" -ne 0 ]]; then
  exit 1
fi

echo "Verified ${#expected[@]} required release artifacts for ${release_tag}."
