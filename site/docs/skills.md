---
id: skills
title: Skills
sidebar_position: 7
---

MicroClaw auto-discovers local skills from `<skills_dir>/*/SKILL.md`.

Path rules:
- If `skills_dir` is explicitly configured, that path is used.
- If `skills_dir` is not configured, skills default to `<data_dir>/skills` (with `data_dir` defaulting to `~/.microclaw`).

Use `/skills` in chat to list all available skills.  
When a request matches a skill, the model can call `activate_skill` to load and follow that skill's full workflow.

## Current bundled skills

MicroClaw ships **42 factory-ready built-in skills** so a fresh install is already a one-stop assistant — compute, coding, research, planning, writing, diagrams, and document handling — with nothing to wire up.

Built-in skills live under `skills/built-in/<name>/SKILL.md`, are embedded into the binary at compile time via `include_dir!`, and are auto-installed at runtime by compatibility (incompatible ones — e.g. the Apple skills on Linux — are silently skipped).

| Category | Skills |
|---|---|
| Documents | `pdf` · `docx` · `pptx` · `xlsx` |
| Apple (macOS-only) | `apple-notes` · `apple-reminders` · `apple-calendar` |
| Tools / platform | `weather` · `github` |
| Retrieval / tracing | `propagation-trace` |
| Meta | `skill-creator` · `find-skills` |
| Compute & data | `calculator` · `unit-converter` · `datetime` · `csv-tools` · `json-tools` · `sql` · `data-analysis` |
| Coding | `code-review` · `regex` · `debugging` · `shell-scripting` · `api-design` · `testing` · `git` |
| Research | `research` · `wikipedia` · `define` |
| Planning | `planning` · `brainstorming` · `decision-matrix` · `meeting-notes` · `goal-setting` |
| Creative & diagrams | `mermaid` · `color-tools` · `algorithmic-art` · `qrcode` |
| Writing & productivity | `writing-editor` · `summarize` · `email-drafting` · `translate` |

Skills that need an external command (`git` / `jq` / `curl` / `qrencode` / `sqlite3`) carry fallback logic in their body, so they degrade gracefully rather than failing when the command is missing. Adding a new built-in skill is a "drop a folder in `skills/built-in/`" operation — auto-discovered, auto-embedded, auto-installed, no Rust changes.

## Selected skills in detail

### `apple-notes`

- Purpose: manage Apple Notes on macOS
- Typical tasks: create/search/edit/move/delete/export notes
- Dependency: `memo`

Install:

```bash
brew tap antoniorodr/memo
brew install antoniorodr/memo/memo
```

Examples:

```bash
memo notes
memo notes -s "weekly plan"
memo notes -a "Project Ideas"
memo notes -e
```

### `apple-reminders`

- Purpose: manage Apple Reminders on macOS
- Typical tasks: list/add/edit/complete/delete reminders and manage lists
- Dependency: `remindctl`

Install:

```bash
brew install steipete/tap/remindctl
```

Examples:

```bash
remindctl today
remindctl add "Buy milk"
remindctl complete 1
remindctl list
```

### `apple-calendar`

- Purpose: read and create Apple Calendar events on macOS
- Typical tasks: query upcoming events and create events
- Dependencies: `icalBuddy` (query), `osascript` (built-in on macOS)

Install:

```bash
brew install ical-buddy
```

Examples:

```bash
icalBuddy eventsToday
icalBuddy eventsFrom:today to:7 days from now
osascript -e 'tell application "Calendar" to tell calendar "Work" to make new event with properties {summary:"Team Sync", start date:date "Monday, February 10, 2026 10:00:00", end date:date "Monday, February 10, 2026 10:30:00"}'
```

### `weather`

- Purpose: quick weather lookup without API keys
- Typical tasks: current weather and short forecast by city
- Dependency: `curl`

Examples:

```bash
curl -s "wttr.in/San+Francisco?format=3"
curl -s "wttr.in/San+Francisco?format=%l:+%c+%t+%h+%w"
curl -s "wttr.in/San+Francisco?m"
```

### `find-skills`

- Purpose: discover reusable skills from [vercel-labs/skills](https://github.com/vercel-labs/skills) and map them into MicroClaw-compatible workflows
- Typical tasks: search by keyword, compare candidates, recommend best-fit + fallback, propose adaptation steps
- Dependency: `curl`

Examples:

```bash
curl -sL "https://raw.githubusercontent.com/vercel-labs/skills/main/README.md"
curl -s "https://api.github.com/search/code?q=repo:vercel-labs/skills+playwright"
```

## Sync skills from registry

Use the `sync_skills` tool to import remote skills and normalize metadata (`source`, `version`, `updated_at`, `platforms`, `deps`).

Example tool input:

```json
{
  "skill_name": "find-skills",
  "source_repo": "vercel-labs/skills",
  "git_ref": "main",
  "target_name": "find-skills"
}
```

## Notes

- Apple-related skills are macOS-only.
- First use may require granting Terminal automation/privacy permissions in macOS System Settings.
- You can add your own skills by creating a new subdirectory under `~/.microclaw/skills/` with a `SKILL.md` file.
