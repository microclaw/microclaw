#!/bin/bash
set -euo pipefail

# -------------------------------------------------------------------
# release_homebrew.sh
#
# 1. Bump patch version in Cargo.toml
# 2. Build web/dist
# 3. cargo build --release
# 3. Create a tar.gz of the binary
# 4. Create a GitHub release and upload the tarball
# 5. Update the homebrew-tap Formula with new version + sha256
# 6. Push tap changes
# -------------------------------------------------------------------

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
REPO_DIR="$ROOT_DIR"
TAP_DIR_DEFAULT="$ROOT_DIR/../../github/homebrew-tap"
TAP_DIR="${TAP_DIR:-$TAP_DIR_DEFAULT}"
TAP_REPO="everettjf/homebrew-tap"
FORMULA_PATH="Formula/microclaw.rb"
GITHUB_REPO="microclaw/microclaw"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
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
fi

# --- Bump patch version in Cargo.toml ---
CURRENT_VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_VERSION"
NEW_PATCH=$((PATCH + 1))
NEW_VERSION="$MAJOR.$MINOR.$NEW_PATCH"
TAG="v$NEW_VERSION"

sed -i '' "s/^version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" Cargo.toml
echo "Version bumped: $CURRENT_VERSION -> $NEW_VERSION"

# --- Build release binary ---
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
echo "SHA256: $SHA256"

# --- Git commit + tag ---
git add Cargo.toml
git commit -m "bump version to $NEW_VERSION"
git tag "$TAG"
git push
git push --tags

# --- GitHub release ---
if gh release view "$TAG" --repo "$GITHUB_REPO" >/dev/null 2>&1; then
  echo "Release $TAG already exists. Skipping create."
else
  gh release create "$TAG" "$TARBALL_PATH" \
    --repo "$GITHUB_REPO" \
    -t "$TAG" \
    -n "MicroClaw $TAG"
  echo "Created GitHub release: $TAG"
fi

# --- Update homebrew-tap ---
if [ ! -d "$TAP_DIR/.git" ]; then
  echo "Cloning tap repo..."
  git clone "https://github.com/$TAP_REPO.git" "$TAP_DIR"
fi

cd "$TAP_DIR"

# Create Formula dir if it doesn't exist
mkdir -p Formula

# Write the formula
cat > "$FORMULA_PATH" << RUBY
class Microclaw < Formula
  desc "Agentic AI assistant for Telegram — web search, scheduling, memory, tool execution"
  homepage "https://github.com/$GITHUB_REPO"
  url "https://github.com/$GITHUB_REPO/releases/download/$TAG/$TARBALL_NAME"
  sha256 "$SHA256"
  license "MIT"

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
git push

echo ""
echo "Done! Released $TAG and updated Homebrew tap."
echo ""
echo "Users can install with:"
echo "  brew tap everettjf/tap"
echo "  brew install microclaw"
