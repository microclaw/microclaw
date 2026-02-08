#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODE="${1:-all}" # all|release

usage() {
  cat <<'EOF'
Usage:
  ./deploy.sh [all|release]

Modes:
  all      Publish GitHub Release asset (installer mode) + update Homebrew tap (default)
  release  Alias of all (kept for clarity)

Notes:
  - This script delegates to scripts/release_homebrew.sh.
  - Configure TAP_DIR if your local tap checkout is not in the default path.
EOF
}

case "$MODE" in
  -h|--help|help)
    usage
    exit 0
    ;;
  all|release)
    ;;
  *)
    echo "Unknown mode: $MODE" >&2
    usage >&2
    exit 1
    ;;
esac

cd "$ROOT_DIR"

if [ ! -x "$ROOT_DIR/scripts/release_homebrew.sh" ]; then
  echo "Missing executable: scripts/release_homebrew.sh" >&2
  exit 1
fi

echo "Starting deploy ($MODE)..."
"$ROOT_DIR/scripts/release_homebrew.sh"



git add .
git commit -m "deployed"
git push



echo "Deploy complete."


cd website
sh ./deploy_pages.sh
cd ..

echo "ALL DONE"
