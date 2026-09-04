---
name: apple-reminders
description: "Manage Apple Reminders on macOS using `remindctl` (list, add, edit, complete, delete, and list management). Use when users ask to create reminders, check tasks, mark items done, manage to-do lists, or perform task-list operations in Apple Reminders. Triggers on mentions of reminders, to-do, tasks, remind me, or checklist."
license: Proprietary. LICENSE.txt has complete terms
platforms:
  - darwin
deps:
  - remindctl
---

# Apple Reminders (remindctl)

Use this skill when users ask to manage Apple Reminders.

## Prerequisites

- macOS
- `remindctl` installed:

```bash
brew install steipete/tap/remindctl
```

- Grant Reminders access if prompted.

## Authorization checks

```bash
remindctl status
remindctl authorize
```

## Core commands

Today / tomorrow / week:

```bash
remindctl today
remindctl tomorrow
remindctl week
```

Add reminder:

```bash
remindctl add "Buy milk"
remindctl add --title "Pay rent" --list Personal --due tomorrow
```

Edit reminder:

```bash
remindctl edit 1 --title "Pay rent (landlord)" --due 2026-02-10
```

Complete reminder:

```bash
remindctl complete 1
```

Delete reminder:

```bash
remindctl delete 1 --force
```

List operations:

```bash
remindctl list
remindctl list Work
remindctl list Projects --create
```

JSON output for scripting:

```bash
remindctl today --json
```

## Usage guidance

- Prefer read/list before mutate/delete.
- Confirm IDs and list names before edit/complete/delete.
- If permission is denied, enable Terminal in:
  System Settings > Privacy & Security > Reminders.
