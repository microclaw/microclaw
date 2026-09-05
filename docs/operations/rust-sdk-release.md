# Rust SDK release

The public Rust SDK has three dependency-ordered crates: `microclaw-core`,
`microclaw-engine`, and `microclaw-sdk`. Publish all three at the same version
from an immutable release tag. Application and implementation-only workspace
crates use `publish = false`.

## One-time repository setup

1. Create a GitHub environment named `crates-io` and require maintainer
   approval for deployments.
2. Add `CARGO_REGISTRY_TOKEN` as an environment secret. Prefer a scoped
   crates.io token owned by the MicroClaw release account.
3. Keep the package names in `scripts/publish_sdk_crates.sh` in dependency
   order when adding another public crate.

## Before tagging

Run the normal CI and the local publication preflight:

```sh
scripts/ci/check_sdk_consumers.sh
scripts/publish_sdk_crates.sh --check
```

All public SDK crates must have the same version. Update their internal
dependency requirements together and record user-visible changes in
`CHANGELOG.md`.

## Publish

1. Create the reviewed release tag with the **Tag Release** workflow.
2. Wait for required CI on the tagged commit.
3. Run **Publish Rust SDK Crates** with the exact tag and SDK version, and type
   `publish` in the confirmation input.
4. Approve the protected `crates-io` environment deployment.

The workflow validates the tag and versions, checks public API compatibility
against the latest crates.io release, then publishes dependencies before
`microclaw-sdk`. The first release has no SemVer baseline and explicitly skips
that comparison.

Publication is resumable. crates.io versions are immutable, so a retry skips
versions already present and continues after the registry index exposes each
dependency. Never yank a successfully published dependency merely because a
later crate failed; correct the failure and rerun the same tagged workflow.

## Verify

After the workflow succeeds, create a new project outside this repository and
resolve the registry release rather than a path dependency:

```toml
[dependencies]
microclaw-sdk = { version = "0.6.1", features = ["full"] }
```

Run `cargo check`, open the matching docs.rs build, and confirm the release
notes point to the SDK guide and Worker compatibility notes.
