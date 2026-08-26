#!/usr/bin/env bash
set -euo pipefail

work_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work_repo_root="$(cd "$work_script_dir/.." && pwd)"
work_profile="${1:-debug}"

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

cd "$work_repo_root"
cargo "${work_cargo_args[@]}"

if [[ ! -x "$work_binary" ]]; then
  echo "expected executable not found: $work_binary" >&2
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

plutil -lint "$work_contents/Info.plist"
test "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$work_contents/Info.plist")" = "org.microclaw.work"
test "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$work_contents/Info.plist")" = "$work_version"
codesign --force --deep --sign - "$work_bundle"
codesign --verify --deep --strict "$work_bundle"

echo "$work_bundle"
