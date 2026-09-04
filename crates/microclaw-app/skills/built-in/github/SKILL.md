---
name: github
description: "Interact with GitHub using the `gh` CLI. Use when users ask about pull requests, issues, CI/CD status, workflow runs, repository information, or want to create, review, or merge PRs. Covers `gh issue`, `gh pr`, `gh run`, and `gh api` for issues, pull requests, actions, checks, releases, and advanced queries. Triggers on mentions of GitHub, pull request, PR, issue, workflow, actions, checks, or merge."
---

# GitHub Skill

Use the `gh` CLI to interact with GitHub. Always specify `--repo owner/repo` when not in a git directory, or use URLs directly.

## Pull Requests

Check CI status on a PR:
```bash
gh pr checks 55 --repo owner/repo
```

List recent workflow runs:
```bash
gh run list --repo owner/repo --limit 10
```

View a run and see which steps failed:
```bash
gh run view <run-id> --repo owner/repo
```

View logs for failed steps only:
```bash
gh run view <run-id> --repo owner/repo --log-failed
```

## API for Advanced Queries

The `gh api` command is useful for accessing data not available through other subcommands.

Get PR with specific fields:
```bash
gh api repos/owner/repo/pulls/55 --jq '.title, .state, .user.login'
```

## Debugging a Failed CI Run

1. Check PR status: `gh pr checks <pr-number> --repo owner/repo`
2. List recent runs: `gh run list --repo owner/repo --limit 5`
3. View the failed run: `gh run view <run-id> --repo owner/repo`
4. Get failed step logs: `gh run view <run-id> --repo owner/repo --log-failed`

## JSON Output

Most commands support `--json` for structured output. Use `--jq` to filter:

```bash
gh issue list --repo owner/repo --json number,title --jq '.[] | "\(.number): \(.title)"'
```
