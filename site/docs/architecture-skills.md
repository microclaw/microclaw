---
id: architecture-skills
title: Architecture - Skills System
sidebar_position: 11
---

Skills provide workflow intelligence without hardcoding every domain behavior into the core engine.

## Skill contract

A skill is a directory with `SKILL.md` frontmatter + instructions.

Required/important metadata:

- `name`
- `description`
- `platforms` (optional, filtered)
- `deps` (optional command checks)
- `source` / `version` / `updated_at` (for provenance)

## Runtime behavior

- Skill catalog is surfaced in system prompt.
- Agent calls `activate_skill` only when needed.
- Platform/dependency filters hide incompatible skills from runtime catalog.

## Source types

- `builtin`: shipped with MicroClaw data bootstrap.
- `local`: user-authored skill in local skills directory.
- `remote`: synchronized via `sync_skills` and normalized locally.

## Why this boundary matters

Core framework should provide:

- discovery
- metadata parsing/validation
- activation APIs
- compatibility filtering

Core framework should not embed domain-specific business workflows.
Those belong in skills.
