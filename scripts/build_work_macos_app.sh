#!/usr/bin/env bash
set -euo pipefail

work_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work_repo_root="$(cd "$work_script_dir/.." && pwd)"
work_profile="${1:-debug}"
work_signing_identity="${MICROCLAW_WORK_SIGNING_IDENTITY:--}"

case "$work_profile" in
  debug)
    work_cargo_args=(build -p microclaw-work --locked)
    ;;
  release)
    work_cargo_args=(build -p microclaw-work --release --locked)
    ;;
  *)
    echo "usage: $0 [debug|release]" >&2
    exit 2
    ;;
esac

work_version="$(awk -F '"' '/^version = / { print $2; exit }' "$work_repo_root/apps/microclaw-work/Cargo.toml")"
if [[ -z "$work_version" ]]; then
  echo "failed to read MicroClaw Work version" >&2
  exit 1
fi

work_output_root="$work_repo_root/target/microclaw-work-app/$work_profile"
work_bundle="$work_output_root/MicroClaw Work.app"
work_contents="$work_bundle/Contents"
work_binary="$work_repo_root/target/$work_profile/microclaw-work"
work_plist_template="$work_repo_root/packaging/microclaw-work/macos/Info.plist.in"
work_icon_source="$work_repo_root/site/static/img/logo.png"
work_iconset="$work_output_root/MicroClawWork.iconset"

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

if [[ "$work_output_root" != "$work_repo_root/target/microclaw-work-app/$work_profile" ]]; then
  echo "refusing to replace unexpected output path: $work_output_root" >&2
  exit 1
fi

rm -rf "$work_output_root"
mkdir -p "$work_contents/MacOS" "$work_contents/Resources"
cp "$work_binary" "$work_contents/MacOS/microclaw-work"
chmod 755 "$work_contents/MacOS/microclaw-work"
sed "s/@VERSION@/$work_version/g" "$work_plist_template" > "$work_contents/Info.plist"

mkdir -p "$work_iconset"
for work_icon_size in 16 32 128 256 512; do
  sips -z "$work_icon_size" "$work_icon_size" "$work_icon_source" \
    --out "$work_iconset/icon_${work_icon_size}x${work_icon_size}.png" >/dev/null
  work_icon_size_2x=$((work_icon_size * 2))
  sips -z "$work_icon_size_2x" "$work_icon_size_2x" "$work_icon_source" \
    --out "$work_iconset/icon_${work_icon_size}x${work_icon_size}@2x.png" >/dev/null
done
iconutil -c icns "$work_iconset" -o "$work_contents/Resources/MicroClawWork.icns"
rm -rf "$work_iconset"

plutil -lint "$work_contents/Info.plist"
test "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$work_contents/Info.plist")" = "org.microclaw.work"
test "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$work_contents/Info.plist")" = "$work_version"
work_codesign_args=(--force --deep --sign "$work_signing_identity")
if [[ "$work_signing_identity" != "-" ]]; then
  work_codesign_args+=(--options runtime --timestamp)
fi
codesign "${work_codesign_args[@]}" "$work_bundle"
codesign --verify --deep --strict "$work_bundle"
codesign -dv --verbose=2 "$work_bundle" 2>&1 | grep -F "Identifier=org.microclaw.work"

echo "$work_bundle"
