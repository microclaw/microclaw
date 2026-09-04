---
name: git
description: "Everyday Git workflows and recovery: status/diff/log, branching, committing, merging vs rebasing, undoing mistakes, resolving conflicts, and inspecting history. Use when users ask how to do something in Git, are stuck (detached HEAD, merge conflict, accidental commit), or want to undo/recover work. Triggers on mentions of git, commit, branch, merge, rebase, conflict, undo, revert, stash, HEAD, 提交, 分支, 合并, 冲突, 撤销, 回滚."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "Requires git. Works on macOS, Linux, and Windows."
---

# Git

Look before you leap: `git status` and `git log --oneline -5` before any destructive action.

## Inspect

```bash
git status
git diff                 # unstaged changes
git diff --staged        # staged changes
git log --oneline -10
git log --oneline --graph --all -20
```

## Branch & commit

```bash
git switch -c feature/x          # create + switch (modern; = checkout -b)
git add -p                       # stage hunks interactively
git commit -m "message"
git switch main && git merge feature/x
```

## Undo safely (most common rescues)

```bash
git restore <file>               # discard unstaged changes to a file
git restore --staged <file>      # unstage (keep changes)
git commit --amend               # fix the last commit message/contents (only if unpushed)
git reset --soft HEAD~1          # undo last commit, KEEP changes staged
git revert <sha>                 # safe undo of a pushed commit (new commit)
git reflog                       # find "lost" commits after a bad reset
```

## Merge conflicts

```bash
git status                       # see conflicted files
# edit files, remove <<<<<<< ======= >>>>>>> markers, keep the right code
git add <file> && git commit     # (or: git rebase --continue)
git merge --abort                # bail out and start over
```

## Guidance

- Prefer `git revert` over `git reset --hard` for anything already pushed/shared.
- `reset --hard` and `clean -fd` are destructive — confirm the branch and stash first
  (`git stash`).
- Write small, focused commits with imperative messages ("Add X", not "added X").
- When unsure where you are: `git status`, `git branch`, `git reflog` orient you.
