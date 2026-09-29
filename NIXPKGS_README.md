# Nixpkgs Automation

This repository includes automation for keeping `microclaw` updated in `NixOS/nixpkgs`.

## One-command Flow

Run from repo root:

```sh
scripts/update-nixpkgs.sh
```

By default, the script will:
- detect version from `Cargo.toml`
- clone `<your-gh-user>/nixpkgs` into `/tmp/nixpkgs-<timestamp>`
- branch from `upstream/master`
- update `pkgs/by-name/mi/microclaw/package.nix`, seeding it from
  `nix/nixpkgs/package.nix` if the package is not upstream yet
- resolve `hash`, `cargoHash` and `npmDeps.hash`
- run `nix-build -A microclaw` and `result/bin/microclaw --help`
- commit, push, and open a PR to `NixOS/nixpkgs` (or update the open PR for that branch)

## Deploy Integration

After release, you can trigger nixpkgs automation with:

```sh
AUTO_NIXPKGS_UPDATE=1 ./deploy.sh
```

## Updating the open init PR

nixpkgs reviewers want new versions force-pushed onto the existing PR branch
(NixOS/nixpkgs#498144, branch `microclaw-init`) rather than a new PR:

```sh
scripts/update-nixpkgs.sh --branch microclaw-init --base master --ready
```

## Useful Flags

```sh
scripts/update-nixpkgs.sh --version 0.6.2
scripts/update-nixpkgs.sh --draft
scripts/update-nixpkgs.sh --ready
scripts/update-nixpkgs.sh --no-pr
scripts/update-nixpkgs.sh --nixpkgs-dir ~/focus/nixpkgs
scripts/update-nixpkgs.sh --template nix/nixpkgs/package.nix
```

## Failure Recovery

If the script fails mid-way:
- check printed temp dir path, inspect git/logs there
- re-run script (it creates a new timestamped temp repo by default)
- optionally run with `--nixpkgs-dir` to reuse a local checkout
