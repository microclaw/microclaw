# Release Policy

## Release Shape

MicroClaw releases from tagged commits (`v*`).

Each release should have:

- green required CI jobs
- generated release notes
- packaged binaries for supported platforms
- official container images for Linux (`linux/amd64`, `linux/arm64`)
- upgrade notes when migrations or config changes are involved
- rollback instructions recorded in the PR or release checklist

## Supported Platforms

Current release asset target set:

- Linux x86_64
- macOS x86_64
- macOS arm64
- Windows x86_64

If a target is temporarily missing, the release notes should say so explicitly.

## Release Gates

Release candidates should satisfy:

- `cargo fmt --all --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`
- `npm --prefix web run build`
- `npm --prefix website run build`
- `node scripts/generate_docs_artifacts.mjs --check`
- security dependency audit
- release asset packaging smoke
- container image build/publish smoke

## Rollback Standard

Every release should preserve:

- previous binary or package availability
- DB backup instructions
- the release commit SHA
- the effective config diff or migration note

If request success, scheduler recoverability, or auth boundaries regress, pause release rollout and revert to the last known good release.
