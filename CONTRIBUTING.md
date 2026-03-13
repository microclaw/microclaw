# Contributing

## Before You Start

- Keep changes scoped.
- Prefer small PRs over large mixed refactors.
- For behavior changes, update user-facing docs in `docs/` and `website/docs/`.
- For security-sensitive or migration-sensitive changes, include rollback notes in the PR description.

## Local Setup

```sh
cp microclaw.config.example.yaml microclaw.config.yaml
cargo build
npm --prefix web ci
npm --prefix website ci
```

## Required Checks

Run these before opening a PR:

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
npm --prefix web run build
npm --prefix website run build
node scripts/generate_docs_artifacts.mjs --check
```

For sandbox or policy changes, also run:

```sh
scripts/ci/stability_smoke.sh
```

## PR Expectations

- Explain the user impact, not just the code delta.
- Call out migrations, config changes, and incompatible behavior.
- Add or update tests for bug fixes and non-trivial changes.
- Include docs updates when operators or users would need to act differently.

## Commit and Review Guidance

- Keep commit messages terse and descriptive.
- Avoid mixing formatting-only changes with behavioral changes unless unavoidable.
- Do not force-push over reviewer context unless the branch history is explicitly disposable.

## Release-Oriented Changes

If you touch release assets, installers, auth, schema migrations, or sandbox behavior, review:

- `docs/releases/pr-release-checklist.md`
- `docs/releases/upgrade-guide.md`
- `docs/operations/runbook.md`
