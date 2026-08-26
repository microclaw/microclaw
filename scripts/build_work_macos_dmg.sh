#!/usr/bin/env bash
set -euo pipefail

work_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work_repo_root="$(cd "$work_script_dir/.." && pwd)"
work_profile="${1:-release}"
work_signing_identity="${MICROCLAW_WORK_SIGNING_IDENTITY:--}"
work_notary_profile="${MICROCLAW_WORK_NOTARY_PROFILE:-}"
work_reclaim_build_artifacts="${MICROCLAW_WORK_RECLAIM_BUILD_ARTIFACTS:-0}"

case "$work_profile" in
  debug|release|work-release) ;;
  *)
    echo "usage: $0 [debug|release|work-release]" >&2
    exit 2
    ;;
esac

work_version="${MICROCLAW_WORK_VERSION_OVERRIDE:-$(awk -F '"' '/^version = / { print $2; exit }' "$work_repo_root/apps/microclaw-work/Cargo.toml")}"
if [[ -z "$work_version" ]]; then
  echo "failed to read MicroClaw Work version" >&2
  exit 1
fi

work_bundle="$work_repo_root/target/microclaw-work-app/$work_profile/MicroClaw Work.app"
work_output_root="$work_repo_root/target/microclaw-work-installer/$work_profile"
work_staging="$work_output_root/staging"
work_dmg="$work_output_root/MicroClaw-Work-$work_version-macos.dmg"

"$work_script_dir/build_work_macos_app.sh" "$work_profile"

if [[ "$work_reclaim_build_artifacts" == "1" ]]; then
  work_cargo_profile_dir="$work_repo_root/target/$work_profile"
  case "$work_cargo_profile_dir" in
    "$work_repo_root/target/debug"|"$work_repo_root/target/release"|"$work_repo_root/target/work-release") ;;
    *)
      echo "refusing to remove unexpected Cargo profile path: $work_cargo_profile_dir" >&2
      exit 1
      ;;
  esac
  rm -rf "$work_cargo_profile_dir"
fi

if [[ -n "$work_notary_profile" ]]; then
  if [[ "$work_signing_identity" == "-" ]]; then
    echo "MICROCLAW_WORK_NOTARY_PROFILE requires a Developer ID signing identity" >&2
    exit 2
  fi
  work_notary_archive="$(mktemp /tmp/microclaw-work-notary.XXXXXX.zip)"
  trap 'rm -f "$work_notary_archive"' EXIT
  ditto -c -k --keepParent "$work_bundle" "$work_notary_archive"
  xcrun notarytool submit "$work_notary_archive" \
    --keychain-profile "$work_notary_profile" \
    --wait
  xcrun stapler staple "$work_bundle"
  xcrun stapler validate "$work_bundle"
fi

if [[ "$work_output_root" != "$work_repo_root/target/microclaw-work-installer/$work_profile" ]]; then
  echo "refusing to replace unexpected output path: $work_output_root" >&2
  exit 1
fi

rm -rf "$work_output_root"
mkdir -p "$work_staging"
ditto "$work_bundle" "$work_staging/MicroClaw Work.app"
ln -s /Applications "$work_staging/Applications"

hdiutil create \
  -volname "MicroClaw Work" \
  -srcfolder "$work_staging" \
  -ov \
  -format UDZO \
  "$work_dmg"

if [[ "$work_signing_identity" != "-" ]]; then
  codesign --force --sign "$work_signing_identity" --timestamp "$work_dmg"
  codesign --verify --verbose=2 "$work_dmg"
fi

if [[ -n "$work_notary_profile" ]]; then
  xcrun notarytool submit "$work_dmg" \
    --keychain-profile "$work_notary_profile" \
    --wait
  xcrun stapler staple "$work_dmg"
  xcrun stapler validate "$work_dmg"
  spctl --assess --type open --context context:primary-signature --verbose=2 "$work_dmg"
fi

hdiutil verify "$work_dmg"
echo "$work_dmg"
