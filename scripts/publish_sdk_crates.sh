#!/usr/bin/env bash
set -euo pipefail

mode="${1:---check}"
if [[ "${mode}" != "--check" && "${mode}" != "--execute" ]]; then
  echo "usage: $0 [--check|--execute]" >&2
  exit 2
fi

crates=(
  microclaw-core
  microclaw-observability
  microclaw-storage
  microclaw-tools
  microclaw-channels
  microclaw-clawhub
  microclaw-app
  microclaw-runtime
  microclaw-engine
  microclaw-worker
  microclaw-sdk
)

crates_io_curl=(
  curl
  --fail
  --silent
  --user-agent "microclaw-release/0.1 (https://github.com/microclaw/microclaw)"
)

workspace_version="$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.name == "microclaw-sdk") | .version')"
if [[ -z "${workspace_version}" || "${workspace_version}" == "null" ]]; then
  echo "could not resolve microclaw-sdk version" >&2
  exit 1
fi

for crate_name in "${crates[@]}"; do
  crate_version="$(cargo metadata --no-deps --format-version 1 | jq -r --arg name "${crate_name}" '.packages[] | select(.name == $name) | .version')"
  if [[ "${crate_version}" != "${workspace_version}" ]]; then
    echo "${crate_name} is ${crate_version}; expected ${workspace_version}" >&2
    exit 1
  fi
done

package_args=(--locked)
if [[ "${mode}" == "--check" ]]; then
  package_args+=(--allow-dirty)
fi
cargo package -p microclaw-core "${package_args[@]}"
cargo package -p microclaw-observability "${package_args[@]}"

if [[ "${mode}" == "--check" ]]; then
  echo "SDK crate metadata and leaf packages are valid at ${workspace_version}."
  echo "Run with --execute only from the protected publication workflow."
  exit 0
fi

if [[ -z "${CARGO_REGISTRY_TOKEN:-}" ]]; then
  echo "CARGO_REGISTRY_TOKEN is required" >&2
  exit 1
fi

for crate_name in "${crates[@]}"; do
  if "${crates_io_curl[@]}" "https://crates.io/api/v1/crates/${crate_name}/${workspace_version}" >/dev/null; then
    echo "${crate_name} ${workspace_version} is already published; skipping"
    continue
  fi
  cargo publish -p "${crate_name}" --locked
  for attempt in $(seq 1 30); do
    if "${crates_io_curl[@]}" "https://crates.io/api/v1/crates/${crate_name}/${workspace_version}" >/dev/null; then
      break
    fi
    if [[ "${attempt}" == "30" ]]; then
      echo "timed out waiting for ${crate_name} ${workspace_version} to reach the index" >&2
      exit 1
    fi
    sleep 10
  done
done

echo "Published MicroClaw SDK crate set ${workspace_version}."
