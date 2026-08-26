# MicroClaw Work macOS release and Homebrew Cask

MicroClaw Work ships as architecture-specific, signed, notarized, and stapled
DMGs attached to the normal MicroClaw GitHub release. The release finalizer then
updates `Casks/microclaw-work.rb` in `microclaw/homebrew-tap`.

Users install or upgrade the desktop application with:

```sh
brew tap microclaw/tap
brew install --cask microclaw-work
brew upgrade --cask microclaw-work
```

## Required GitHub Actions secrets

The `Release Assets` workflow intentionally fails the Work jobs when any Apple
release credential is missing. Configure these repository secrets:

- `APPLE_CERTIFICATE_BASE64`: base64-encoded Developer ID Application `.p12`
- `APPLE_CERTIFICATE_PASSWORD`: password protecting the `.p12`
- `APPLE_ID`: Apple account used by `notarytool`
- `APPLE_TEAM_ID`: Apple Developer team identifier
- `APPLE_APP_PASSWORD`: app-specific password used by `notarytool`

The workflow imports the certificate into an ephemeral runner keychain, derives
the Developer ID identity, stores a temporary `notarytool` profile, and runs
`scripts/build_work_macos_dmg.sh work-release`. Both the application bundle and
DMG are submitted, stapled, and validated before upload.

## Release assets

For a tag such as `v0.6.0`, the workflow publishes:

```text
microclaw-work-0.6.0-arm64-macos.dmg
microclaw-work-0.6.0-x86_64-macos.dmg
```

`MICROCLAW_WORK_VERSION_OVERRIDE` binds the application bundle and DMG version
to the release tag without requiring the desktop crate to duplicate the Server
package version between releases.

## Tap update

The existing `scripts/release_homebrew.sh` entry point invokes
`scripts/release_finalize.sh`. The finalizer waits for both Work DMGs, reads the
official GitHub asset digests, and writes a multi-architecture Homebrew Cask.
It pushes the Server formulas and Work Cask together, so a release cannot update
the tap with missing or unverified desktop assets.

For a local signed candidate outside GitHub Actions, install a Developer ID
Application identity and configure a `notarytool` keychain profile:

```sh
MICROCLAW_WORK_SIGNING_IDENTITY="Developer ID Application: Example (TEAMID)" \
MICROCLAW_WORK_NOTARY_PROFILE="microclaw-work" \
MICROCLAW_WORK_VERSION_OVERRIDE="0.6.0" \
scripts/build_work_macos_dmg.sh work-release
```

Do not publish the ad-hoc signed preview produced when these release credentials
are absent.
