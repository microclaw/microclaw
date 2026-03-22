#!/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/release_finalize.sh --repo-dir <path> --tap-dir <path> --tap-repo <owner/repo> \
    --formula-path <path> --github-repo <owner/repo> --new-version <version> --tag <tag> \
    --tarball-name <name>
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

current_branch() {
  local branch
  branch="$(git symbolic-ref --quiet --short HEAD || true)"
  if [ -z "$branch" ]; then
    echo "Detached HEAD is not supported for release push" >&2
    exit 1
  fi
  echo "$branch"
}

sync_rebase_and_push() {
  local remote="${1:-origin}"
  local branch
  branch="$(current_branch)"

  echo "Syncing $remote/$branch before push..."
  git fetch "$remote" "$branch"
  if git show-ref --verify --quiet "refs/remotes/$remote/$branch"; then
    git rebase "$remote/$branch"
  fi

  if git rev-parse --abbrev-ref --symbolic-full-name "@{u}" >/dev/null 2>&1; then
    git push "$remote" "$branch"
  else
    git push -u "$remote" "$branch"
  fi
}

wait_for_ci_success() {
  local github_repo="$1"
  local commit_sha="$2"
  local timeout_seconds="${CI_WAIT_TIMEOUT_SECONDS:-6000}"
  local interval_seconds="${CI_WAIT_INTERVAL_SECONDS:-20}"
  local elapsed=0
  local required_jobs_json='["Web And Docs Build","Docker Build","Security Audit","Rust (ubuntu-latest)","Rust (macos-latest)","Stability Smoke"]'
  local required_job_count

  required_job_count="$(jq -r 'length' <<<"$required_jobs_json")"

  echo "Waiting for required CI jobs on commit: $commit_sha"
  while [ "$elapsed" -lt "$timeout_seconds" ]; do
    local run_id
    run_id="$(
      gh run list \
        --repo "$github_repo" \
        --workflow "CI" \
        --commit "$commit_sha" \
        --json databaseId,status,createdAt \
        --jq 'sort_by(.createdAt) | reverse | .[0].databaseId'
    )"

    if [ -z "$run_id" ] || [ "$run_id" = "null" ]; then
      echo "CI run not found yet for commit $commit_sha."
      sleep "$interval_seconds"
      elapsed=$((elapsed + interval_seconds))
      continue
    fi

    local jobs_json
    jobs_json="$(
      gh run view "$run_id" \
        --repo "$github_repo" \
        --json jobs
    )"

    local failed_job
    failed_job="$(
      jq -r --argjson required "$required_jobs_json" '
        .jobs
        | map(select(.name as $name | $required | index($name)))
        | map(select(.conclusion == "failure"
                  or .conclusion == "cancelled"
                  or .conclusion == "timed_out"
                  or .conclusion == "action_required"
                  or .conclusion == "startup_failure"
                  or .conclusion == "stale"))
        | first
        | if . == null then empty else "\(.name) \(.url)" end
      ' <<<"$jobs_json"
    )"

    if [ -n "$failed_job" ]; then
      echo "Required CI job failed for commit $commit_sha: $failed_job" >&2
      return 1
    fi

    local completed_required_count
    completed_required_count="$(
      jq -r --argjson required "$required_jobs_json" '
        .jobs
        | map(select(.name as $name | $required | index($name)))
        | map(select(.conclusion == "success"))
        | length
      ' <<<"$jobs_json"
    )"

    if [ "$completed_required_count" -eq "$required_job_count" ]; then
      echo "Required CI jobs succeeded. Run id: $run_id"
      return 0
    fi

    echo "CI not successful yet. Slept ${elapsed}s/${timeout_seconds}s."
    sleep "$interval_seconds"
    elapsed=$((elapsed + interval_seconds))
  done

  echo "Timed out waiting for required CI jobs after ${timeout_seconds}s." >&2
  return 1
}

wait_for_release_asset_ready() {
  local github_repo="$1"
  local tag="$2"
  local asset_name="$3"
  local timeout_seconds="${RELEASE_ASSETS_WAIT_TIMEOUT_SECONDS:-7200}"
  local interval_seconds="${RELEASE_ASSETS_WAIT_INTERVAL_SECONDS:-20}"
  local elapsed=0

  echo "Waiting for release asset on tag: $tag ($asset_name)"
  while [ "$elapsed" -lt "$timeout_seconds" ]; do
    local digest
    digest="$(
      gh release view "$tag" \
        --repo "$github_repo" \
        --json assets \
        | jq -r --arg asset_name "$asset_name" '.assets[] | select(.name == $asset_name) | .digest'
    )"

    if [ -n "$digest" ] && [ "$digest" != "null" ]; then
      echo "Release asset is available: $asset_name"
      return 0
    fi

    local runs_json
    runs_json="$(
      gh run list \
        --repo "$github_repo" \
        --workflow "Release Assets" \
        --branch "$tag" \
        --json databaseId,status,conclusion,createdAt,url
    )"

    local run_id
    run_id="$(jq -r 'sort_by(.createdAt) | reverse | .[0].databaseId // empty' <<<"$runs_json")"

    if [ -z "$run_id" ]; then
      echo "Release Assets run not found yet for tag $tag."
      sleep "$interval_seconds"
      elapsed=$((elapsed + interval_seconds))
      continue
    fi

    local jobs_json
    jobs_json="$(
      gh run view "$run_id" \
        --repo "$github_repo" \
        --json jobs
    )"

    local failed_job
    failed_job="$(
      jq -r '
        .jobs
        | map(select(
            (.name | startswith("Build "))
            or .name == "Upload to GitHub Release"
            or .name == "Verify CI Passed"
          ))
        | map(select(
            .conclusion == "failure"
            or .conclusion == "cancelled"
            or .conclusion == "timed_out"
            or .conclusion == "action_required"
            or .conclusion == "startup_failure"
            or .conclusion == "stale"
          ))
        | first
        | if . == null then empty else "\(.name) \(.url)" end
      ' <<<"$jobs_json"
    )"

    if [ -n "$failed_job" ]; then
      echo "Release asset build failed for tag $tag: $failed_job" >&2
      return 1
    fi

    local run_status
    run_status="$(jq -r 'sort_by(.createdAt) | reverse | .[0].status' <<<"$runs_json")"
    echo "Release asset not ready yet (${run_status:-unknown}). Slept ${elapsed}s/${timeout_seconds}s."
    sleep "$interval_seconds"
    elapsed=$((elapsed + interval_seconds))
  done

  echo "Timed out waiting for release asset after ${timeout_seconds}s: $asset_name" >&2
  return 1
}

release_asset_sha256() {
  local github_repo="$1"
  local tag="$2"
  local asset_name="$3"
  local digest

  digest="$(
    gh release view "$tag" \
      --repo "$github_repo" \
      --json assets \
      | jq -r --arg asset_name "$asset_name" '.assets[] | select(.name == $asset_name) | .digest'
  )"

  if [ -z "$digest" ] || [ "$digest" = "null" ]; then
    echo "Unable to find digest for release asset: $asset_name" >&2
    return 1
  fi

  echo "${digest#sha256:}"
}

homebrew_macos_asset_name() {
  local version="$1"
  local arch="$2"
  echo "microclaw-${version}-${arch}-apple-darwin.tar.gz"
}

previous_release_tag() {
  local current_tag="$1"
  git tag --list 'v*' --sort=-version:refname | awk -v current="$current_tag" '$0 != current { print; exit }'
}

write_generated_release_notes() {
  local repo="$1"
  local tag="$2"
  local previous_tag="$3"
  local notes_file="$4"
  local args=(
    gh api -X POST "repos/$repo/releases/generate-notes"
    -f "tag_name=$tag"
  )

  if [ -n "$previous_tag" ]; then
    args+=(-f "previous_tag_name=$previous_tag")
  fi

  "${args[@]}" --jq '.body' > "$notes_file"
}

REPO_DIR=""
TAP_DIR=""
TAP_REPO=""
FORMULA_PATH=""
GITHUB_REPO=""
NEW_VERSION=""
TAG=""
TARBALL_NAME=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo-dir) REPO_DIR="$2"; shift 2 ;;
    --tap-dir) TAP_DIR="$2"; shift 2 ;;
    --tap-repo) TAP_REPO="$2"; shift 2 ;;
    --formula-path) FORMULA_PATH="$2"; shift 2 ;;
    --github-repo) GITHUB_REPO="$2"; shift 2 ;;
    --new-version) NEW_VERSION="$2"; shift 2 ;;
    --tag) TAG="$2"; shift 2 ;;
    --tarball-name) TARBALL_NAME="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

for required in REPO_DIR TAP_DIR TAP_REPO FORMULA_PATH GITHUB_REPO NEW_VERSION TAG TARBALL_NAME; do
  if [ -z "${!required}" ]; then
    echo "Missing required argument: $required" >&2
    usage >&2
    exit 1
  fi
done

require_cmd gh
require_cmd git
require_cmd jq

if ! gh auth status >/dev/null 2>&1; then
  echo "GitHub CLI not authenticated. Run: gh auth login" >&2
  exit 1
fi

cd "$REPO_DIR"

RELEASE_COMMIT_SHA="$(git rev-parse HEAD)"
if ! wait_for_ci_success "$GITHUB_REPO" "$RELEASE_COMMIT_SHA"; then
  exit 1
fi

if git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1; then
  echo "Tag already exists on origin: $TAG"
else
  if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null 2>&1; then
    echo "Tag already exists locally: $TAG"
  else
    git tag "$TAG" "$RELEASE_COMMIT_SHA"
    echo "Created local tag: $TAG -> $RELEASE_COMMIT_SHA"
  fi
  git push origin "refs/tags/$TAG"
  echo "Pushed tag: $TAG"
fi

PREV_TAG="$(previous_release_tag "$TAG")"
if [ -n "$PREV_TAG" ]; then
  echo "Generating release notes from range: $PREV_TAG..$TAG"
else
  echo "Generating release notes without a previous tag (first release or missing tags)"
fi
RELEASE_NOTES_FILE="$(mktemp)"
trap 'rm -f "$RELEASE_NOTES_FILE"' EXIT
write_generated_release_notes "$GITHUB_REPO" "$TAG" "$PREV_TAG" "$RELEASE_NOTES_FILE"

if gh release view "$TAG" --repo "$GITHUB_REPO" >/dev/null 2>&1; then
  echo "Release $TAG exists. Updating release notes."
  gh release edit "$TAG" \
    --repo "$GITHUB_REPO" \
    -t "$TAG" \
    --notes-file "$RELEASE_NOTES_FILE"
else
  echo "Release $TAG does not exist. Creating release with generated notes."
  gh release create "$TAG" \
    --repo "$GITHUB_REPO" \
    -t "$TAG" \
    --notes-file "$RELEASE_NOTES_FILE"
fi

if ! wait_for_release_asset_ready "$GITHUB_REPO" "$TAG" "$TARBALL_NAME"; then
  exit 1
fi

HOMEBREW_ARM64_TARBALL_NAME="$(homebrew_macos_asset_name "$NEW_VERSION" "aarch64")"
HOMEBREW_X86_64_TARBALL_NAME="$(homebrew_macos_asset_name "$NEW_VERSION" "x86_64")"

if ! wait_for_release_asset_ready "$GITHUB_REPO" "$TAG" "$HOMEBREW_ARM64_TARBALL_NAME"; then
  exit 1
fi

if ! wait_for_release_asset_ready "$GITHUB_REPO" "$TAG" "$HOMEBREW_X86_64_TARBALL_NAME"; then
  exit 1
fi

HOMEBREW_ARM64_SHA256="$(release_asset_sha256 "$GITHUB_REPO" "$TAG" "$HOMEBREW_ARM64_TARBALL_NAME")"
HOMEBREW_X86_64_SHA256="$(release_asset_sha256 "$GITHUB_REPO" "$TAG" "$HOMEBREW_X86_64_TARBALL_NAME")"
echo "Official Homebrew arm64 SHA256: $HOMEBREW_ARM64_SHA256"
echo "Official Homebrew x86_64 SHA256: $HOMEBREW_X86_64_SHA256"

echo "Resetting tap workspace: $TAP_DIR"
rm -rf "$TAP_DIR"
mkdir -p "$(dirname "$TAP_DIR")"
echo "Cloning tap repo..."
git clone "https://github.com/$TAP_REPO.git" "$TAP_DIR"

cd "$TAP_DIR"
mkdir -p Formula

cat > "$FORMULA_PATH" << RUBY
class Microclaw < Formula
  desc "Agentic AI assistant for Telegram - web search, scheduling, memory, tool execution"
  homepage "https://github.com/$GITHUB_REPO"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/$GITHUB_REPO/releases/download/$TAG/$HOMEBREW_ARM64_TARBALL_NAME"
      sha256 "$HOMEBREW_ARM64_SHA256"
    else
      url "https://github.com/$GITHUB_REPO/releases/download/$TAG/$HOMEBREW_X86_64_TARBALL_NAME"
      sha256 "$HOMEBREW_X86_64_SHA256"
    end
  end

  def install
    bin.install "microclaw"
  end

  test do
    assert_match "MicroClaw", shell_output("#{bin}/microclaw help")
  end
end
RUBY

git add .
git commit -m "microclaw homebrew release $NEW_VERSION"
sync_rebase_and_push origin

echo ""
echo "Done! Released $TAG and updated Homebrew tap."
echo ""
echo "Users can install with:"
echo "  brew tap microclaw/tap"
echo "  brew install microclaw"
