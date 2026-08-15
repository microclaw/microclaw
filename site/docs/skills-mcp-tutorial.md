---
id: skills-mcp-tutorial
title: Skills + MCP Tutorial
sidebar_position: 3
---

This tutorial covers two extension paths:

1. Add or customize **Skills** (`SKILL.md` workflow packs)
2. Extend **MCP** servers (`mcp.json` + `mcp.d/*.json` tool federation)


Use this page as the operational guide for production setups.

## Part 1: Add a New Skill

### 1) Create the skill folder

```bash
mkdir -p ~/.microclaw/skills/my-skill
```

### 2) Add `SKILL.md`

```markdown
---
name: my-skill
description: One-line summary of what the skill does.
platforms: [darwin, linux, windows]
deps: [curl]
---

# My Skill

When to use:
- ...

Workflow:
1. ...
2. ...
```

Supported frontmatter fields:

- `name` (required)
- `description` (required)
- `platforms` (optional)
- `deps` (optional)
- `compatibility.os` and `compatibility.deps` (optional aliases)

### 3) Restart and verify

```bash
RUST_LOG=info cargo run -- start
```

Then in chat:

```text
/skills
```

If your skill is filtered out, check:

- Platform mismatch (`platforms` does not include current OS)
- Missing commands in `deps`

### 4) Activate manually (sanity check)

Ask the assistant:

```text
activate the skill my-skill and summarize its instructions
```

If activation fails, the error now includes platform/dependency diagnostics.

## Part 2: Use Built-in `find-skills` (vercel-labs/skills)

MicroClaw includes a bundled skill: `find-skills`.

Goal:
- Search [vercel-labs/skills](https://github.com/vercel-labs/skills)
- Pick best-fit skills by task keyword
- Adapt upstream instructions into MicroClaw-compatible local skills

Example prompts:

```text
Find skills for playwright test debugging from vercel-labs/skills.
```

```text
Find a skill for converting docs to PDF and adapt it to this repo.
```

### 5) Sync from external registries (automated)

MicroClaw includes a `sync_skills` tool that can pull a skill from a remote repo and normalize metadata:

```text
sync skill playwright-debug from vercel-labs/skills
```

Equivalent tool input shape:

```json
{
  "skill_name": "playwright-debug",
  "source_repo": "vercel-labs/skills",
  "git_ref": "main",
  "target_name": "playwright-debug"
}
```

The synced `SKILL.md` includes normalized fields:

- `source` (for provenance)
- `version` (git ref)
- `updated_at` (sync time)

## Part 3: Extend MCP

### 1) Start from minimal production config

```bash
cp mcp.minimal.example.json ~/.microclaw/mcp.json
mkdir -p ~/.microclaw/mcp.d
```

This gives you one safe local MCP server (`filesystem` via `stdio`).

MicroClaw loads MCP config from:

- `~/.microclaw/mcp.json`
- `~/.microclaw/mcp.d/*.json` (loaded in filename order; later files override earlier ones for the same server key)

### 2) Add an additional MCP server

```json
{
  "defaultProtocolVersion": "2024-11-05",
  "mcpServers": {
    "filesystem": {
      "transport": "stdio",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "."]
    },
    "my_remote": {
      "transport": "streamable_http",
      "endpoint": "http://127.0.0.1:8080/mcp",
      "headers": {
        "Authorization": "Bearer REPLACE_ME"
      },
      "request_timeout_secs": 60,
      "max_retries": 2,
      "health_interval_secs": 30
    }
  }
}
```

You can place this in either:

- base config: `~/.microclaw/mcp.json`
- a fragment such as `~/.microclaw/mcp.d/10-remote.json`

For sidecar integrations (for example a bridge process), prefer a dedicated fragment:

```bash
cp mcp.hapi-bridge.example.json ~/.microclaw/mcp.d/hapi-bridge.json
```

Accepted key aliases:

- `defaultProtocolVersion` or `default_protocol_version`
- `protocolVersion` or `protocol_version`
- `endpoint` or `url`

Reliability knobs:

- `request_timeout_secs`: per-request timeout
- `max_retries`: retry count for stdio reconnect paths
- `health_interval_secs`: periodic health probe interval (`0` disables probing)

### 3) Restart and verify MCP loading

```bash
RUST_LOG=info cargo run -- start
```

Look for logs:

- `Connecting to MCP server '...'`
- `MCP server '...' connected (...)`

### 4) Confirm tools are exposed

Ask the assistant to list available tools or invoke one MCP namespaced tool.

Tool names are exposed as:

```text
mcp_<server_name>_<tool_name>
```

Example:

```text
mcp_filesystem_read_file
```

## Common pitfalls

- `mcp.json` placed in wrong directory: by default it should be `~/.microclaw/mcp.json` (or `<data_dir>/mcp.json` if you changed `data_dir`)
- `mcp.d/*.json` fragments placed in wrong directory: use `<data_dir>/mcp.d/` (default `~/.microclaw/mcp.d/`)
- Missing runtime dependency (`npx`, server binary, auth token)
- Skill appears in repo but not in `/skills`: usually platform/deps filter
- Remote MCP endpoint responds non-JSON-RPC payload
- High-risk tools (for example `bash`) can require second confirmation in Web/control-chat contexts; pass `__microclaw_approval.token` from the previous error message when prompted

## Recommended workflow for teams

1. Keep `mcp.minimal.example.json` as baseline.
2. Add remote MCP servers one-by-one, with explicit owners.
3. Add skills in small focused folders.
4. Validate each addition with `/skills` + one real task prompt.
5. Track changes in GitHub Releases and project roadmap docs.
