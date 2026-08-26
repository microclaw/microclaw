#!/usr/bin/env bash
set -euo pipefail

work_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work_repo_root="$(cd "$work_script_dir/.." && pwd)"
work_profile="${1:-release}"
work_signing_identity="${MICROCLAW_WORK_SIGNING_IDENTITY:--}"

case "$work_profile" in
  debug|release) ;;
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

work_bundle="$work_repo_root/target/microclaw-work-app/$work_profile/MicroClaw Work.app"
work_output_root="$work_repo_root/target/microclaw-work-installer/$work_profile"
work_staging="$work_output_root/staging"
work_dmg="$work_output_root/MicroClaw-Work-$work_version-macos.dmg"

"$work_script_dir/build_work_macos_app.sh" "$work_profile"

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

hdiutil verify "$work_dmg"
echo "$work_dmg"
