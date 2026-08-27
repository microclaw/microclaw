#!/usr/bin/env bash
set -euo pipefail

work_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work_repo_root="$(cd "$work_script_dir/.." && pwd)"
work_profile="${1:-work-release}"

case "$work_profile" in
  debug|release|work-release) ;;
  *)
    echo "usage: $0 [debug|release|work-release]" >&2
    exit 2
    ;;
esac

work_version="${MICROCLAW_WORK_VERSION_OVERRIDE:-$(awk -F '"' '/^version = / { print $2; exit }' "$work_repo_root/apps/microclaw-work/Cargo.toml")}"
work_bundle="$work_repo_root/target/microclaw-work-app/$work_profile/MicroClaw Work.app"
work_plist="$work_bundle/Contents/Info.plist"
work_binary="$work_bundle/Contents/MacOS/microclaw-work"
work_icon="$work_bundle/Contents/Resources/MicroClawWork.icns"
work_dmg="$work_repo_root/target/microclaw-work-installer/$work_profile/MicroClaw-Work-$work_version-macos.dmg"

for work_path in "$work_plist" "$work_binary" "$work_icon" "$work_dmg"; do
  if [[ ! -e "$work_path" ]]; then
    echo "missing release artifact: $work_path" >&2
    exit 1
  fi
done

if [[ ! -x "$work_binary" ]]; then
  echo "packaged executable is not executable: $work_binary" >&2
  exit 1
fi

work_bundle_id="$(plutil -extract CFBundleIdentifier raw -o - "$work_plist")"
work_bundle_version="$(plutil -extract CFBundleShortVersionString raw -o - "$work_plist")"
work_minimum_macos="$(plutil -extract LSMinimumSystemVersion raw -o - "$work_plist")"

[[ "$work_bundle_id" == "org.microclaw.work" ]] || {
  echo "unexpected bundle identifier: $work_bundle_id" >&2
  exit 1
}
[[ "$work_bundle_version" == "$work_version" ]] || {
  echo "bundle version $work_bundle_version does not match expected $work_version" >&2
  exit 1
}
[[ "$work_minimum_macos" == "13.0" ]] || {
  echo "unexpected minimum macOS version: $work_minimum_macos" >&2
  exit 1
}

codesign --verify --deep --strict --verbose=2 "$work_bundle"
hdiutil verify "$work_dmg"

work_mount="$(mktemp -d /tmp/microclaw-work-release.XXXXXX)"
work_attached=0
cleanup_work_mount() {
  if [[ "$work_attached" == "1" ]]; then
    hdiutil detach "$work_mount" >/dev/null
  fi
  rmdir "$work_mount" 2>/dev/null || true
}
trap cleanup_work_mount EXIT

hdiutil attach -nobrowse -readonly -mountpoint "$work_mount" "$work_dmg" >/dev/null
work_attached=1

[[ -d "$work_mount/MicroClaw Work.app" ]] || {
  echo "DMG does not contain MicroClaw Work.app" >&2
  exit 1
}
[[ -L "$work_mount/Applications" ]] || {
  echo "DMG does not contain the Applications link" >&2
  exit 1
}
[[ "$(readlink "$work_mount/Applications")" == "/Applications" ]] || {
  echo "DMG Applications link has an unexpected target" >&2
  exit 1
}

if [[ "${MICROCLAW_WORK_REQUIRE_NOTARIZATION:-0}" == "1" ]]; then
  xcrun stapler validate "$work_bundle"
  xcrun stapler validate "$work_dmg"
  spctl --assess --type execute --verbose=2 "$work_bundle"
  spctl --assess --type open --context context:primary-signature --verbose=2 "$work_dmg"
fi

work_sha256="$(shasum -a 256 "$work_dmg" | awk '{ print $1 }')"
echo "MicroClaw Work release verification passed"
echo "  profile: $work_profile"
echo "  version: $work_version"
echo "  minimum macOS: $work_minimum_macos"
echo "  dmg sha256: $work_sha256"
