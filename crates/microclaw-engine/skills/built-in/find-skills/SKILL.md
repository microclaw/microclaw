---
name: find-skills
description: "Find reusable skills from the vercel-labs/skills registry by task keywords, evaluate fit, and suggest how to install or adapt them for MicroClaw. Use when users ask 'do we have a skill for X?', 'find skills for a given task', or want to discover existing skills instead of writing from scratch. Triggers on mentions of find skill, search skills, skill registry, or reuse skill."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "Requires curl for GitHub API access. Works on macOS, Linux, and Windows."
---

# Find Skills (vercel-labs/skills)

Use this skill when users ask:
- "Do we already have a skill for X?"
- "Find skills for [task]"
- "What existing skill can I reuse instead of writing from scratch?"

Primary source:
- https://github.com/vercel-labs/skills

## Discovery workflow

1. Clarify the target task in one sentence.
2. Search the registry by keywords (task, toolchain, framework, platform).
3. For each candidate skill, extract:
   - Skill name/path
   - What problem it solves
   - Required tools/dependencies
   - Any platform assumptions
4. Recommend one best-fit skill and one fallback.
5. If none fit exactly, propose adaptation steps for MicroClaw.

## Useful commands

Search repo metadata quickly:

```bash
curl -s "https://api.github.com/repos/vercel-labs/skills/contents" 
```

Search issues/paths by keyword (example):

```bash
curl -s "https://api.github.com/search/code?q=repo:vercel-labs/skills+keyword"
```

Fetch raw README/skill docs when needed:

```bash
curl -sL "https://raw.githubusercontent.com/vercel-labs/skills/main/README.md"
```

## Output format

When returning results, use this structure:

1. Best match
2. Why it fits
3. Requirements
4. Install/adapt steps for MicroClaw
5. Alternative options

## MicroClaw adaptation hints

- Convert upstream skill metadata to local `SKILL.md` frontmatter (`name`, `description`, optional `platforms`/`deps`).
- Keep instructions actionable with `bash`, file tools, and existing MCP tools.
- If upstream skill assumes another runtime, add a short "MicroClaw notes" section describing equivalent commands.
