#!/usr/bin/env bash
# Build "MicroClaw Code.app" from this crate (unsigned).
#   scripts/bundle.sh [debug|release]   → target/<profile>/MicroClaw Code.app
# Signing, notarization and the DMG are a follow-up (see the desktop plan).
set -euo pipefail
cd "$(dirname "$0")/.."
profile="${1:-release}"
if [[ "$profile" == release ]]; then
  cargo build --release
else
  cargo build
fi
version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
app="target/$profile/MicroClaw Code.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "target/$profile/microclaw-code-desktop" "$app/Contents/MacOS/"
sed "s/0\.30\.0/$version/g" resources/Info.plist > "$app/Contents/Info.plist"
# Ad-hoc signature so Gatekeeper on this machine runs it; not for distribution.
codesign --force --sign - "$app" >/dev/null 2>&1 || true
echo "$app"
