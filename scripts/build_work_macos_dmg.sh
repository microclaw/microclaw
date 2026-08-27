#!/usr/bin/env bash
set -euo pipefail

work_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work_repo_root="$(cd "$work_script_dir/.." && pwd)"
work_profile="${1:-release}"
work_signing_identity="${MICROCLAW_WORK_SIGNING_IDENTITY:--}"
work_notary_profile="${MICROCLAW_WORK_NOTARY_PROFILE:-}"
work_notary_keychain="${MICROCLAW_WORK_NOTARY_KEYCHAIN:-}"
work_notary_apple_id="${MICROCLAW_WORK_NOTARY_APPLE_ID:-}"
work_notary_password="${MICROCLAW_WORK_NOTARY_PASSWORD:-}"
work_notary_team_id="${MICROCLAW_WORK_NOTARY_TEAM_ID:-}"
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

  if [[ "${CI:-}" == "true" && -n "${CARGO_HOME:-}" ]]; then
    work_cargo_home="$(cd "$CARGO_HOME" && pwd -P)"
    case "$work_cargo_home" in
      /|"$work_repo_root"|"$work_repo_root"/*)
        echo "refusing to remove caches from unexpected Cargo home: $work_cargo_home" >&2
        exit 1
        ;;
    esac
    rm -rf \
      "$work_cargo_home/registry/cache" \
      "$work_cargo_home/registry/src" \
      "$work_cargo_home/git/checkouts" \
      "$work_cargo_home/git/db"
  fi

  df -h "$work_repo_root"
fi

work_notarize=false
work_notary_auth=()
if [[ -n "$work_notary_profile" ]]; then
  work_notarize=true
  if [[ "$work_signing_identity" == "-" ]]; then
    echo "MICROCLAW_WORK_NOTARY_PROFILE requires a Developer ID signing identity" >&2
    exit 2
  fi
  work_notary_auth=(--keychain-profile "$work_notary_profile")
  if [[ -n "$work_notary_keychain" ]]; then
    if [[ ! -f "$work_notary_keychain" ]]; then
      echo "MICROCLAW_WORK_NOTARY_KEYCHAIN does not exist: $work_notary_keychain" >&2
      exit 2
    fi
    work_notary_auth+=(--keychain "$work_notary_keychain")
  fi
elif [[ -n "$work_notary_apple_id" || -n "$work_notary_password" || -n "$work_notary_team_id" ]]; then
  if [[ -z "$work_notary_apple_id" || -z "$work_notary_password" || -z "$work_notary_team_id" ]]; then
    echo "direct notarization requires MICROCLAW_WORK_NOTARY_APPLE_ID, MICROCLAW_WORK_NOTARY_PASSWORD, and MICROCLAW_WORK_NOTARY_TEAM_ID" >&2
    exit 2
  fi
  if [[ "$work_signing_identity" == "-" ]]; then
    echo "direct notarization requires a Developer ID signing identity" >&2
    exit 2
  fi
  work_notarize=true
  work_notary_auth=(
    --apple-id "$work_notary_apple_id"
    --password "$work_notary_password"
    --team-id "$work_notary_team_id"
  )
fi

if [[ "$work_notarize" == true ]]; then
  work_notary_archive="$(mktemp /tmp/microclaw-work-notary.XXXXXX.zip)"
  trap 'rm -f "$work_notary_archive"' EXIT
  ditto -c -k --keepParent "$work_bundle" "$work_notary_archive"
  xcrun notarytool submit "$work_notary_archive" \
    "${work_notary_auth[@]}" \
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

if [[ "$work_notarize" == true ]]; then
  xcrun notarytool submit "$work_dmg" \
    "${work_notary_auth[@]}" \
    --wait
  xcrun stapler staple "$work_dmg"
  xcrun stapler validate "$work_dmg"
  spctl --assess --type open --context context:primary-signature --verbose=2 "$work_dmg"
fi

hdiutil verify "$work_dmg"
echo "$work_dmg"
