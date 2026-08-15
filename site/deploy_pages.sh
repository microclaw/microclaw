#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WEBSITE_DIR="$SCRIPT_DIR"

INSTALLER_FILES=(
  install.sh
  install.ps1
  uninstall.sh
  uninstall.ps1
)

for installer_file in "${INSTALLER_FILES[@]}"; do
  cp "$ROOT_DIR/$installer_file" "$WEBSITE_DIR/static/$installer_file"
done

cd "$WEBSITE_DIR"

# Only commit the installer artifacts managed by this script. Never sweep
# unrelated working-tree changes into an automatic deployment commit.
if ! git diff --quiet -- "${INSTALLER_FILES[@]/#/static/}"; then
  git add -- "${INSTALLER_FILES[@]/#/static/}"
  git commit -m "Sync installer artifacts" -- "${INSTALLER_FILES[@]/#/static/}"
fi

if [ -n "$(git status --porcelain)" ]; then
  echo "The website working tree has uncommitted changes." >&2
  echo "Commit or stash them before deploying so the published build matches a source commit." >&2
  exit 1
fi

echo "Pushing website source..."
git push

if [ ! -d node_modules ]; then
  echo "Installing dependencies..."
  npm ci
fi

echo "Building site..."
npm run build

DEPLOY_ATTEMPTS="${DEPLOY_ATTEMPTS:-3}"
DEPLOY_RETRY_DELAY_SECONDS="${DEPLOY_RETRY_DELAY_SECONDS:-5}"

if ! [[ "$DEPLOY_ATTEMPTS" =~ ^[1-9][0-9]*$ ]]; then
  echo "DEPLOY_ATTEMPTS must be a positive integer." >&2
  exit 1
fi

if ! [[ "$DEPLOY_RETRY_DELAY_SECONDS" =~ ^[0-9]+$ ]]; then
  echo "DEPLOY_RETRY_DELAY_SECONDS must be a non-negative integer." >&2
  exit 1
fi

# Keep SSH sessions alive while GitHub processes a larger Pages pack. Set
# USE_SSH=false (and optionally GIT_USER) to use HTTPS credentials instead.
export USE_SSH="${USE_SSH:-true}"
if [ "$USE_SSH" = "true" ]; then
  export GIT_SSH_COMMAND="${GIT_SSH_COMMAND:-ssh -o ServerAliveInterval=15 -o ServerAliveCountMax=4}"
else
  export GIT_USER="${GIT_USER:-microclaw}"
fi

echo "Deploying to GitHub Pages (gh-pages)..."
deploy_attempt=1
while [ "$deploy_attempt" -le "$DEPLOY_ATTEMPTS" ]; do
  echo "Deployment attempt $deploy_attempt of $DEPLOY_ATTEMPTS..."
  if npm run deploy -- --skip-build; then
    echo "Live at https://microclaw.org"
    exit 0
  fi

  if [ "$deploy_attempt" -eq "$DEPLOY_ATTEMPTS" ]; then
    echo "Deployment failed after $DEPLOY_ATTEMPTS attempts." >&2
    exit 1
  fi

  echo "Deployment attempt failed; retrying in ${DEPLOY_RETRY_DELAY_SECONDS}s..." >&2
  sleep "$DEPLOY_RETRY_DELAY_SECONDS"
  deploy_attempt=$((deploy_attempt + 1))
done
