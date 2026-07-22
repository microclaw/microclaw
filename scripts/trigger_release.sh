#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/trigger_release.sh [options]

Options:
  --version <version>        Release version (default: Cargo.toml package version)
  --repo <owner/name>        GitHub repository (default: current gh repository)
  --sha <commit>             Commit to release (default: HEAD)
  --wait                     Wait for all release assets and container images
  --ci-timeout <minutes>     CI wait timeout (default: 30)
  -h, --help                 Show this help
EOF
}

version=""
repository=""
sha="HEAD"
wait_for_release=false
ci_timeout_minutes=30

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      version="${2:?--version requires a value}"
      shift 2
      ;;
    --repo)
      repository="${2:?--repo requires a value}"
      shift 2
      ;;
    --sha)
      sha="${2:?--sha requires a value}"
      shift 2
      ;;
    --wait)
      wait_for_release=true
      shift
      ;;
    --ci-timeout)
      ci_timeout_minutes="${2:?--ci-timeout requires a value}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

for command in git gh; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command is not available: $command" >&2
    exit 1
  fi
done

if ! [[ "$ci_timeout_minutes" =~ ^[1-9][0-9]*$ ]]; then
  echo "--ci-timeout must be a positive integer" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ -n "$(git status --porcelain)" ]]; then
  echo "The worktree must be clean before a release" >&2
  exit 1
fi

resolved_sha="$(git rev-parse "$sha")"
if [[ -z "$repository" ]]; then
  repository="$(gh repo view --json nameWithOwner --jq '.nameWithOwner')"
fi

manifest_version="$(sed -nE 's/^version[[:space:]]*=[[:space:]]*"([^"]+)"/\1/p' Cargo.toml | head -n 1)"
if [[ -z "$manifest_version" ]]; then
  echo "Unable to read package version from Cargo.toml" >&2
  exit 1
fi
if [[ -z "$version" ]]; then
  version="$manifest_version"
fi
version="${version#v}"
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.+][0-9A-Za-z.-]+)?$ ]]; then
  echo "Invalid semantic version: $version" >&2
  exit 2
fi
if [[ "$version" != "$manifest_version" ]]; then
  echo "Requested version $version does not match Cargo.toml version $manifest_version" >&2
  exit 1
fi
tag="v$version"

git fetch origin main --tags
if ! git merge-base --is-ancestor "$resolved_sha" origin/main; then
  echo "Release commit $resolved_sha is not present on origin/main" >&2
  exit 1
fi
gh auth status

latest_run_field() {
  local workflow="$1"
  local commit="$2"
  local field="$3"
  local output=""
  local attempt
  for attempt in 1 2 3 4 5; do
    if output="$(gh run list \
      --repo "$repository" \
      --workflow "$workflow" \
      --limit 20 \
      --json databaseId,headSha,status,conclusion,createdAt,url \
      --jq ".[] | select(.headSha == \"$commit\") | .$field" 2>/dev/null | head -n 1)"; then
      printf '%s' "$output"
      return 0
    fi
    echo "Unable to list $workflow runs (attempt $attempt/5); retrying in 3 seconds" >&2
    sleep 3
  done
  echo "Unable to list workflow runs for $workflow after retries" >&2
  return 1
}

wait_for_ci() {
  local commit="$1"
  local timeout_seconds=$((ci_timeout_minutes * 60))
  local elapsed=0
  while (( elapsed < timeout_seconds )); do
    local run_id status conclusion url
    run_id="$(latest_run_field ci.yml "$commit" databaseId)"
    if [[ -z "$run_id" ]]; then
      echo "Waiting for CI run for $commit ..."
    else
      status="$(latest_run_field ci.yml "$commit" status)"
      conclusion="$(latest_run_field ci.yml "$commit" conclusion)"
      url="$(latest_run_field ci.yml "$commit" url)"
      if [[ "$status" == "completed" ]]; then
        if [[ "$conclusion" != "success" ]]; then
          echo "CI did not pass: $url ($conclusion)" >&2
          exit 1
        fi
        echo "CI passed: $url"
        return 0
      fi
      echo "Waiting for CI: $url ($status)"
    fi
    sleep 15
    elapsed=$((elapsed + 15))
  done
  echo "Timed out waiting for CI after $ci_timeout_minutes minutes" >&2
  exit 1
}

wait_for_ci "$resolved_sha"

if git show-ref --verify --quiet "refs/tags/$tag"; then
  echo "Tag already exists: $tag"
else
  echo "Creating $tag at $resolved_sha ..."
  gh workflow run tag-release.yml \
    --repo "$repository" \
    -f "tag=$tag" \
    -f "sha=$resolved_sha"
  sleep 3
  tag_run_id="$(latest_run_field tag-release.yml "$resolved_sha" databaseId)"
  if [[ -z "$tag_run_id" ]]; then
    echo "Tag workflow was dispatched but its run could not be found" >&2
    exit 1
  fi
  gh run watch "$tag_run_id" --repo "$repository" --exit-status
fi

echo "Triggering multi-platform assets for $tag ..."
gh workflow run release-assets.yml --repo "$repository" -f "tag=$tag"
sleep 3
release_run_id="$(latest_run_field release-assets.yml "$resolved_sha" databaseId)"
if [[ -z "$release_run_id" ]]; then
  echo "Release workflow was dispatched but its run could not be found" >&2
  exit 1
fi
release_url="$(latest_run_field release-assets.yml "$resolved_sha" url)"
echo "Release workflow: $release_url"

if [[ "$wait_for_release" == true ]]; then
  gh run watch "$release_run_id" --repo "$repository" --exit-status
  gh release view "$tag" --repo "$repository"
else
  echo "Use --wait to wait for all Windows, macOS, Linux, container, and release assets."
fi
