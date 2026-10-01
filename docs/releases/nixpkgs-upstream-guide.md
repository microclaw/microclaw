# Nixpkgs Upstream Guide

Last reviewed: 2026-09-29

This guide covers how to upstream `microclaw` to `NixOS/nixpkgs` so users get cache-backed prebuilt binaries from official Nix infrastructure.

## Goal

- Package `microclaw` in `nixpkgs`
- Keep updates low-friction on each release
- Ensure Linux + Darwin builds stay healthy

## Current status

- Upstream PR: [NixOS/nixpkgs#498144](https://github.com/NixOS/nixpkgs/pull/498144)
  (`microclaw: init at 0.0.163`, branch `everettjf/nixpkgs:microclaw-init`, still a draft).
- The nixpkgs reviewer asked that newer versions be force-pushed onto that same
  branch (then retitle the PR and mark it ready) instead of opening a new PR.
- Nothing is merged yet, so `nixos-unstable` has no `microclaw` package.
  The update script therefore seeds the package from
  [`nix/nixpkgs/package.nix`](../../nix/nixpkgs/package.nix) when it is missing upstream.

To bring the draft up to the current release:

```sh
scripts/update-nixpkgs.sh --branch microclaw-init --base master --ready
```

This rebuilds `microclaw-init` on top of `upstream/master`, carries over the
`maintainers/maintainer-list.nix` entry from the old branch, resolves the three
hashes, builds, pushes with `--force-with-lease`, retitles the PR to
`microclaw: init at <version>` and marks it ready for review.

## Package expression

The canonical expression lives in `nix/nixpkgs/package.nix` and is copied into
`pkgs/by-name/mi/microclaw/package.nix` (no `all-packages.nix` entry is needed
for `by-name` packages). Points that differ from a plain `buildRustPackage`:

- **Web UI bundle.** `build.rs` embeds `web/dist` (feature `embedded-web-ui`,
  on by default) and will try to run `npm` itself. nixpkgs builds have no
  network, so the expression pre-fetches the npm cache with `fetchNpmDeps`
  (`npmDepsHash`), runs `npm --prefix web run build` in `preBuild`, and sets
  `MICROCLAW_SKIP_WEB_BUILD=1` so `build.rs` only verifies the bundle.
- **Git dependencies.** `Cargo.lock` pins Git revisions of GPUI/Zed crates for
  the desktop app. `cargoHash` (fetchCargoVendor) vendors them behind one hash;
  `cargoBuildFlags = [ "--package" "microclaw" ]` keeps the desktop crates out
  of the actual build. Expect the vendor step to be large the first time.
- **Three hashes** to resolve on every bump: `src.hash`, `cargoHash`,
  `npmDeps.hash`. The script does this by looping on `specified:`/`got:` pairs.
- Linux-only features `journald` and `sqlite-vec` stay behind
  `stdenv.hostPlatform.isLinux`. The only native library linked is OpenSSL
  (SQLite is bundled by rusqlite/sqlite-vec); don't add `buildInputs` that
  `Cargo.lock` doesn't actually need.
- Tests run in the sandbox (`cargoTestFlags` scoped to the server package).
  Tests that need network go in `checkFlags` as `--skip=...`; today that is
  only `media_client_accepts_public_https` (DNS lookup).
- `versionCheckHook` runs `microclaw --version` after install, and
  `passthru.updateScript = nix-update-script { }` lets the nixpkgs update
  bot bump version and hashes once the package is merged.
- Minimum Rust is `rust-version` in `Cargo.toml` (1.93 today); check that the
  target nixpkgs branch ships at least that `rustc`.

## Hash Update Workflow (manual)

When new release `vX.Y.Z` is out:

1. Bump `version`.
2. Set `hash`, `cargoHash` and `npmDeps.hash` to `lib.fakeHash` (or distinct
   placeholders so each error is attributable).
3. Run build:

```sh
nix-build -A microclaw
```

4. Copy the "got: sha256-..." values from the error output into the field
   whose "specified:" value matches.
5. Rebuild until it succeeds.

Automated path from the MicroClaw repo:

```sh
scripts/update-nixpkgs.sh                                   # bump on a fresh branch
scripts/update-nixpkgs.sh --branch microclaw-init --base master --ready   # update the open PR
```

## Validation Before Opening Nixpkgs PR

- Build on Linux and Darwin (`x86_64-linux`, `aarch64-darwin` at minimum).
- Verify executable:

```sh
result/bin/microclaw --help
```

- Confirm Linux-only features (`journald`, `sqlite-vec`) stay guarded on Darwin.

## Ongoing Maintenance Policy

- Keep `flake.nix` package version aligned with `Cargo.toml`.
- On each MicroClaw release, open/update a nixpkgs bump PR within 24h.
- If upstream crate graph changes break nixpkgs, keep `flake` build green first, then patch nixpkgs expression.

## Recommended PR Metadata

- Title: `microclaw: init at <version>` (until the init PR merges) / `microclaw: <old> -> <new>` (bump)
- Include:
  - release notes link
  - local build logs for Linux/Darwin
  - short risk note if feature flags changed
