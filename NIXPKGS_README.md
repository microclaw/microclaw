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
scripts/update-nixpkgs.sh --branch microclaw-init --base master --ready \
  --assisted-by "Claude Code:claude-opus-5-5"
```

## Automation/AI policy

nixpkgs requires an `Assisted-by: <tool>:<model>` commit trailer for every
LLM-assisted commit (`Co-authored-by` does not count) and a separate disclosure
in the PR description; see
[CONTRIBUTING.md#automationai-policy](https://github.com/NixOS/nixpkgs/blob/master/CONTRIBUTING.md#automationai-policy).

- Pass `--assisted-by "<tool>:<model>"` once per tool/model used for the
  release (for example `--assisted-by "Claude Code:claude-opus-5-5"`). The
  script adds the trailers with `git interpret-trailers`. Without the flag it
  carries over the `Assisted-by:` trailers of the old branch tip and warns.
- An open PR keeps its description: only the version in the release link and
  in "init at" is bumped, and an "AI disclosure" section is inserted before
  "Things done" if the body has none. A body that is not based on the nixpkgs
  PR template is rebuilt from `.github/PULL_REQUEST_TEMPLATE.md`.
- To review before pushing, run with `--no-push --nixpkgs-dir <checkout>`:
  check `git log -1` there and the rendered PR body in
  `<checkout>/.git/microclaw-pr-body.md`.

## Useful Flags

```sh
scripts/update-nixpkgs.sh --version 0.6.2
scripts/update-nixpkgs.sh --draft
scripts/update-nixpkgs.sh --ready
scripts/update-nixpkgs.sh --no-pr
scripts/update-nixpkgs.sh --nixpkgs-dir ~/focus/nixpkgs
scripts/update-nixpkgs.sh --template nix/nixpkgs/package.nix
scripts/update-nixpkgs.sh --assisted-by "Claude Code:claude-opus-5-5"
scripts/update-nixpkgs.sh --no-push --nixpkgs-dir ~/focus/nixpkgs   # review commit + PR body locally
```

## Failure Recovery

If the script fails mid-way:
- check printed temp dir path, inspect git/logs there
- re-run script (it creates a new timestamped temp repo by default)
- optionally run with `--nixpkgs-dir` to reuse a local checkout
