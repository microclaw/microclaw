---
name: apple-notes
description: "Manage Apple Notes on macOS using the `memo` CLI. Use when users ask to create, list, search, edit, move, delete, or export Apple Notes. Triggers on mentions of notes, Apple Notes, memo, jot something down, or note-taking."
license: Proprietary. LICENSE.txt has complete terms
platforms:
  - darwin
deps:
  - memo
---

# Apple Notes (memo CLI)

Use this skill when users want to manage Apple Notes from chat.

## Prerequisites

- macOS
- `memo` installed:

```bash
brew tap antoniorodr/memo
brew install antoniorodr/memo/memo
```

- First run may require granting Automation permission to Notes.app.

## Core commands

List notes:

```bash
memo notes
```

Search notes:

```bash
memo notes -s "project kickoff"
```

Filter by folder:

```bash
memo notes -f "Work"
```

Create a note (interactive):

```bash
memo notes -a
```

Create a note with title:

```bash
memo notes -a "Weekly Plan"
```

Edit note (interactive picker):

```bash
memo notes -e
```

Move note to another folder (interactive):

```bash
memo notes -m
```

Delete note (interactive):

```bash
memo notes -d
```

Export note:

```bash
memo notes -ex
```

## Usage guidance

- Prefer search/list first before destructive actions.
- Confirm intent before delete/move operations.
- If command fails with permission issues, instruct user to enable Terminal in:
  System Settings > Privacy & Security > Automation.
