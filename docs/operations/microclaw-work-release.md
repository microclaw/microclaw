# MicroClaw Work desktop release and Homebrew Cask

MicroClaw Work ships as a locally built, signed, notarized, and stapled Apple
Silicon DMG attached to the normal MicroClaw GitHub release. The release finalizer then
updates `Casks/microclaw-work.rb` in `microclaw/homebrew-tap`.

Users install or upgrade the desktop application with:

```sh
brew tap microclaw/tap
brew install --cask microclaw-work
brew upgrade --cask microclaw-work
```

## Local Apple credentials

Apple signing and notarization intentionally run on the release Mac rather than
GitHub Actions. The local environment needs:

- an installed `Developer ID Application` identity;
- an Apple ID, team ID, and app-specific password stored in a `notarytool`
  keychain profile.

The release operator runs `scripts/build_work_macos_dmg.sh work-release`. Both
the application bundle and DMG are submitted, stapled, and validated locally
before the DMG is uploaded to the GitHub release. No Apple credentials are
stored in repository secrets.

## Release assets

For a tag such as `v0.6.0`, the workflow publishes:

```text
microclaw-work-0.6.0-arm64-macos.dmg
microclaw-work-0.6.0-x86_64-linux-gnu.tar.gz
microclaw-work-0.6.0-aarch64-linux-gnu.tar.gz
microclaw-work-0.6.0-x86_64-windows-msvc.zip
```

`MICROCLAW_WORK_VERSION_OVERRIDE` binds the application bundle and DMG version
to the release tag without requiring the desktop crate to duplicate the Server
package version between releases.

The macOS DMGs are the supported desktop distribution and pass Developer ID
signing, Apple notarization, stapling, bundle verification, and launch smoke.
The Linux and Windows archives are portable previews: the release matrix builds
them with the pinned Rust toolchain, launch-smokes them on their native GitHub
runners, and includes them in `SHA256SUMS.txt`. Linux archives contain a GNU
dynamically linked executable and therefore still depend on compatible system
glibc, Vulkan, font, and windowing libraries. Windows portable binaries are not
code-signed installers and can trigger SmartScreen until that release path is
promoted to supported status.

## Tap update

The release finalizer waits for the Apple Silicon Work DMG, reads the official
GitHub asset digest, and writes an Apple Silicon Homebrew Cask.
It pushes the Server formulas and Work Cask together, so a release cannot update
the tap with missing or unverified desktop assets.

For a local signed candidate outside GitHub Actions, install a Developer ID
Application identity and configure a `notarytool` keychain profile:

```sh
xcrun notarytool store-credentials "microclaw-work-notary" \
  --apple-id "APPLE_ID" \
  --team-id "APPLE_TEAM_ID" \
  --password "APP_SPECIFIC_PASSWORD"

MICROCLAW_WORK_SIGNING_IDENTITY="Developer ID Application: Example (TEAMID)" \
MICROCLAW_WORK_NOTARY_PROFILE="microclaw-work-notary" \
MICROCLAW_WORK_VERSION_OVERRIDE="0.6.0" \
scripts/build_work_macos_dmg.sh work-release
MICROCLAW_WORK_REQUIRE_NOTARIZATION=1 \
scripts/verify_work_macos_release.sh work-release
```

For a one-off local release without storing another Keychain profile, set
`MICROCLAW_WORK_NOTARY_APPLE_ID`, `MICROCLAW_WORK_NOTARY_PASSWORD`, and
`MICROCLAW_WORK_NOTARY_TEAM_ID` instead of
`MICROCLAW_WORK_NOTARY_PROFILE`. The script passes these values only to the
current `notarytool` processes and never writes them into release assets.

For non-interactive local release shells that cannot write the login Keychain,
create and unlock a temporary keychain, store the profile there with
`notarytool store-credentials --keychain <path>`, and pass the same path as
`MICROCLAW_WORK_NOTARY_KEYCHAIN`. The build script supplies that keychain to
both application and DMG submissions. Delete the temporary keychain after the
release completes.

Do not publish the ad-hoc signed preview produced when these release credentials
are absent.

## Rollback

If a Work release is defective, revert the Homebrew tap commit that introduced
its Cask version and push the revert before changing or deleting release
assets. This makes `brew update` stop offering the defective build while
keeping immutable release evidence available for diagnosis.

Publish a corrected patch release through the normal signed and notarized
pipeline. Do not replace a DMG under an existing tag: the Cask SHA-256 and the
GitHub asset must remain an immutable pair. Users who already upgraded can
install the preceding notarized DMG from its GitHub release, then install the
corrected Cask when available. Work conversation and settings data remain in
the platform data directory; neither Cask removal nor rollback should delete
that directory.

Before reopening the Cask, run the release verifier above. Then verify `brew
install --cask microclaw-work`, `brew upgrade --cask microclaw-work`, and `brew
uninstall --cask microclaw-work` from a clean macOS user account. Confirm that
the Server formula and binary version are unchanged.
