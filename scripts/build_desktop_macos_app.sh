#!/usr/bin/env bash
set -euo pipefail

work_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work_repo_root="$(cd "$work_script_dir/.." && pwd)"
work_profile="${1:-debug}"
work_signing_identity="${MICROCLAW_DESKTOP_SIGNING_IDENTITY:--}"

case "$work_profile" in
  debug)
    work_cargo_args=(build -p microclaw-desktop --locked)
    ;;
  release)
    work_cargo_args=(build -p microclaw-desktop --release --locked)
    ;;
  work-release)
    work_cargo_args=(build -p microclaw-desktop --profile work-release --locked)
    ;;
  *)
    echo "usage: $0 [debug|release|work-release]" >&2
    exit 2
    ;;
esac

work_version="${MICROCLAW_DESKTOP_VERSION_OVERRIDE:-$(awk -F '"' '/^version = / { print $2; exit }' "$work_repo_root/apps/microclaw-desktop/Cargo.toml")}"
if [[ -z "$work_version" ]]; then
  echo "failed to read MicroClaw Desktop version" >&2
  exit 1
fi

work_output_root="$work_repo_root/target/microclaw-desktop-app/$work_profile"
work_bundle="$work_output_root/MicroClaw Desktop.app"
work_contents="$work_bundle/Contents"
work_binary="$work_repo_root/target/$work_profile/microclaw-desktop"
work_plist_template="$work_repo_root/packaging/microclaw-desktop/macos/Info.plist.in"
work_icon_source="$work_repo_root/packaging/microclaw-desktop/macos/MicroClawDesktop.png"

cd "$work_repo_root"
cargo "${work_cargo_args[@]}"

if [[ ! -x "$work_binary" ]]; then
  echo "expected executable not found: $work_binary" >&2
  exit 1
fi

if [[ ! -f "$work_icon_source" ]]; then
  echo "expected website logo not found: $work_icon_source" >&2
  exit 1
fi

if [[ "$work_output_root" != "$work_repo_root/target/microclaw-desktop-app/$work_profile" ]]; then
  echo "refusing to replace unexpected output path: $work_output_root" >&2
  exit 1
fi

rm -rf "$work_output_root"
mkdir -p "$work_contents/MacOS" "$work_contents/Resources"
cp "$work_binary" "$work_contents/MacOS/microclaw-desktop"
chmod 755 "$work_contents/MacOS/microclaw-desktop"
sed "s/@VERSION@/$work_version/g" "$work_plist_template" > "$work_contents/Info.plist"

sips -s format icns "$work_icon_source" \
  --out "$work_contents/Resources/MicroClawDesktop.icns" >/dev/null

plutil -lint "$work_contents/Info.plist"
test "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$work_contents/Info.plist")" = "org.microclaw.desktop"
test "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$work_contents/Info.plist")" = "$work_version"
work_codesign_args=(--force --deep --sign "$work_signing_identity")
if [[ "$work_signing_identity" != "-" ]]; then
  work_codesign_args+=(--options runtime --timestamp)
fi
codesign "${work_codesign_args[@]}" "$work_bundle"
codesign --verify --deep --strict "$work_bundle"
codesign -dv --verbose=2 "$work_bundle" 2>&1 | grep -F "Identifier=org.microclaw.desktop"

echo "$work_bundle"
