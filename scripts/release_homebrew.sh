#!/bin/bash
set -euo pipefail

# -------------------------------------------------------------------
# release_homebrew.sh
#
# 1. Bump patch version in Cargo.toml
# 2. Build web/dist
# 3. cargo build --release
# 4. Create a tar.gz of the binary
# 5. Create/update the GitHub release metadata
# 6. Wait for CI release assets and update the homebrew-tap Formula with the official sha256
# 7. Push tap changes
# -------------------------------------------------------------------

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
REPO_DIR="$ROOT_DIR"
TAP_DIR="$ROOT_DIR/tmp/homebrew-tap"
TAP_REPO="microclaw/homebrew-tap"
FORMULA_PATH="Formula/microclaw.rb"
GITHUB_REPO="microclaw/microclaw"

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

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "x86_64" ;;
    arm64|aarch64) echo "aarch64" ;;
    *)
      echo "Unsupported architecture: $(uname -m)" >&2
      exit 1
      ;;
  esac
}

latest_release_tag() {
  git tag --list 'v*' --sort=-version:refname | head -n1
}

contains_digit_four() {
  [[ "$1" == *4* ]]
}

require_cmd cargo
require_cmd git
require_cmd gh
require_cmd shasum
require_cmd tar
require_cmd npm

if ! gh auth status >/dev/null 2>&1; then
  echo "GitHub CLI not authenticated. Run: gh auth login" >&2
  exit 1
fi

cd "$REPO_DIR"

# --- Build web assets (embedded via include_dir! in src/web.rs) ---
if [ -f "web/package.json" ]; then
  echo "Building web assets..."
  if [ -f "web/package-lock.json" ]; then
    npm --prefix web ci
  else
    npm --prefix web install
  fi
  npm --prefix web run build
  test -f "web/dist/index.html" || {
    echo "web/dist/index.html is missing after web build" >&2
    exit 1
  }
  test -f "web/dist/icon.png" || {
    echo "web/dist/icon.png is missing after web build" >&2
    exit 1
  }
  if ! ls web/dist/assets/*.js >/dev/null 2>&1; then
    echo "web/dist/assets/*.js is missing after web build" >&2
    exit 1
  fi
fi

# --- Bump patch version in Cargo.toml ---
PREV_TAG="$(latest_release_tag)"
CURRENT_VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_VERSION"

NEW_MAJOR="$MAJOR"
NEW_MINOR="$MINOR"

while contains_digit_four "$NEW_MAJOR"; do
  NEW_MAJOR=$((NEW_MAJOR + 1))
  NEW_MINOR=0
  PATCH=0
done

while contains_digit_four "$NEW_MINOR"; do
  NEW_MINOR=$((NEW_MINOR + 1))
  PATCH=0
done

NEW_PATCH=$((PATCH + 1))
NEW_VERSION="$NEW_MAJOR.$NEW_MINOR.$NEW_PATCH"
while contains_digit_four "$NEW_VERSION"; do
  NEW_PATCH=$((NEW_PATCH + 1))
  NEW_VERSION="$NEW_MAJOR.$NEW_MINOR.$NEW_PATCH"
done
TAG="v$NEW_VERSION"

if [ "$PREV_TAG" = "$TAG" ]; then
  PREV_TAG="$(git tag --list 'v*' --sort=-version:refname | sed -n '2p')"
fi

sed -i '' "s/^version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" Cargo.toml
echo "Version bumped: $CURRENT_VERSION -> $NEW_VERSION"
if [ -n "$PREV_TAG" ]; then
  echo "Previous tag: $PREV_TAG"
else
  echo "Previous tag: (none)"
fi

# --- Build release binary ---
echo "Cleaning previous Rust build artifacts..."
cargo clean

echo "Building release binary..."
cargo build --release

BINARY="target/release/microclaw"
if [ ! -f "$BINARY" ]; then
  echo "Binary not found: $BINARY" >&2
  exit 1
fi

# --- Create tarball ---
ARCH="$(detect_arch)"
TARBALL_NAME="microclaw-$NEW_VERSION-${ARCH}-apple-darwin.tar.gz"
TARBALL_PATH="target/release/$TARBALL_NAME"

tar -czf "$TARBALL_PATH" -C target/release microclaw
echo "Created tarball: $TARBALL_PATH"

SHA256=$(shasum -a 256 "$TARBALL_PATH" | awk '{print $1}')
echo "Local tarball SHA256: $SHA256"

# --- Git commit + push ---
git add .
git commit -m "bump version to $NEW_VERSION"
sync_rebase_and_push origin

echo "Release commit pushed: $(git rev-parse HEAD)"

# --- Finalize release (blocking) ---
"$ROOT_DIR/scripts/release_finalize.sh" \
  --repo-dir "$REPO_DIR" \
  --tap-dir "$TAP_DIR" \
  --tap-repo "$TAP_REPO" \
  --formula-path "$FORMULA_PATH" \
  --github-repo "$GITHUB_REPO" \
  --new-version "$NEW_VERSION" \
  --tag "$TAG" \
  --tarball-name "$TARBALL_NAME"
