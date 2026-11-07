---
id: code-editors
title: Use with Zed
sidebar_label: Use with Zed
---

# Use with Zed

[Zed](https://zed.dev) is the recommended way to use MicroClaw Code. Zed runs
it in its Agent Panel, next to Zed's own agent, and shows its edits as diffs
you can review in the editor. The terminal interface stays available for the
same sessions.

Besides Zed, `mccode` speaks two protocols on stdio, so other programs can use
it without the terminal interface:

| Command | Protocol | For |
|---|---|---|
| `mccode acp` | [Agent Client Protocol](https://agentclientprotocol.com) | Editors with an agent panel: Zed, and other ACP clients |
| `mccode mcp-server` | [Model Context Protocol](https://modelcontextprotocol.io) | Other agents: Claude Code, Codex, Cursor, any MCP client |

Both use the same engine, settings, trust decisions and sessions as the
terminal interface. Install `mccode` and run `mccode setup` first (see
[Overview and install](./code)); check the result with `mccode doctor`.

## Zed

Zed runs external agents through ACP and shows them in its Agent Panel.

### 1. Add MicroClaw Code as an agent

Find the installed binary with `which mccode`, then open Zed's settings
(`zed: open settings`, or `~/.config/zed/settings.json`) and add:

```json
{
  "agent_servers": {
    "MicroClaw Code": {
      "type": "custom",
      "command": "/Users/you/.local/bin/mccode",
      "args": ["acp"],
      "env": {}
    }
  }
}
```

- Use the full path: Zed started from the Dock or the desktop does not read
  your shell profile, so a bare `mccode` is often not found.
- Older Zed releases do not know `"type"`; leave that line out there.
- Global options go **before** `acp`:

  ```json
  "args": ["--mode", "auto", "--no-network", "acp"]
  ```

  Useful ones: `--mode plan|ask|auto` (starting mode), `--no-network`,
  `--sandbox off`, `--no-verify`, `--config <PATH>` (model settings).
- `env` passes environment variables, for example
  `"MCCODE_HOME": "/path/to/another/home"` or an API key referenced
  by your configuration.

### 2. Start a thread

1. Open a folder that is (inside) a git repository.
2. Open the Agent Panel, click **+** and choose **MicroClaw Code**.
3. Type a task. Mention files with `@` as in Zed's own agent, or add files,
   symbols, images or the branch diff with the **+** button under the message
   box; their content is sent along with the prompt.

Each Zed thread is a MicroClaw Code session in the project of the folder Zed
opened. The thread is named after your first message (or the attached file
when you typed nothing), appears in Zed's thread history, and reopening it
loads the session and replays its messages. Threads started in Zed and
sessions started in the terminal are the same sessions (`mccode sessions`
lists both); **Import Threads** in Zed's thread list brings in sessions you
started in the terminal or in other projects.

If no model is configured yet, Zed asks you to sign in: choose **Set up
MicroClaw Code** and Zed runs `mccode setup` in a terminal. Afterwards start
the thread again.

### What you see

- **Mode and model**: the selectors under the message box switch between
  *Plan* (read-only, proposes a plan), *Ask* (edits apply, commands ask) and
  *Auto* (commands run, destructive ones still ask), and between the models of
  the session's provider (your settings profile's models and the known models
  of the same provider). Zed remembers the model you pick.
- **Tool calls**: reads, searches and commands appear as tool cards with their
  status and output; cards carry absolute paths, so Zed can follow the agent.
- **Edits**: each edit shows a real diff of the file (old and new text), which
  Zed renders like its own agent's edits.
- **Checks**: in trusted projects the project's checks run after a change and
  appear as their own cards (`Check tests: …`) with the result; failures go
  back to the agent for a fix round, as in the terminal.
- **Plan**: the agent's todo list is shown as Zed's plan view and updates as
  steps complete.
- **Permission requests**: when a command needs approval, Zed shows a card
  with the command and the options *Approve once*, *Always allow* the tool in
  this thread, *Always allow this command in this project* (single simple
  commands such as `cargo test`) and *Deny*. The agent waits for your answer
  and continues in the same run.
- **Context**: the ring next to the mode picker shows how much of the model's
  context window the session uses; hover it for the numbers (for example
  `1% · 14k / 1M`). `/cost` reports requests and tokens, and the estimated
  cost when the model's price is known.
- **Commands**: type `/` for `/review [focus]`, `/compact [focus]`, `/undo`,
  `/cost`, `/context` and `/help`, plus your custom commands
  (`~/.mccode/commands`, `.microclaw/commands` in trusted projects).
- **Stop**: Zed's stop button cancels the run.

### Trust

Editors cannot show the trust question, so `.microclaw/project.yaml` (mode,
instructions, checks) and `AGENTS.md` only apply to projects you have
already trusted. Trust a project once from a terminal:

```sh
cd path/to/repo
mccode trust          # or open `mccode` and answer the question
```

If the file changes later (for example after a pull), trust it again.

### Troubleshooting

- Run `dev: open acp logs` in Zed's command palette to see the messages
  between Zed and `mccode`.
- Run `mccode doctor` in the same folder: it validates the model
  configuration and starts the engine once.
- "command not found" or the agent never starts: use the absolute path in
  `command`.
- No model configured: run `mccode setup` (or use Zed's sign-in prompt), add
  a profile to `~/.mccode/settings.yaml`, or pass `--config <PATH>` in
  `args`.

## Other ACP editors

Any ACP client works the same way: configure an agent that runs `mccode` with
the argument `acp` (global options before it) in the project's folder. The
client must send the project directory as the session's `cwd`.

## Claude Code, Codex, Cursor and other MCP clients

`mccode mcp-server` exposes two tools:

| Tool | Arguments | What it does |
|---|---|---|
| `run` | `prompt`, optional `cwd`, `mode` (`plan`/`ask`/`auto`), `session` | Runs a coding task in the repository of `cwd`, with verification and fix rounds. Returns the answer, the changed files, the check result and the session id. |
| `review` | optional `focus`, `cwd` | Reviews the uncommitted changes (`git diff HEAD` plus untracked files) with read-only tools and returns findings by severity with `file:line`. |

Approvals: a command that needs one ends the `run` call and says so. Answer
by calling `run` again with the same `session` and the prompt `1` (approve
once), `2` (always allow the tool) or `3` (deny). Use `mode: "auto"` to avoid
most approvals.

### Claude Code

```sh
claude mcp add mccode -- mccode mcp-server
```

Add `--scope project` to share the entry with the repository's
`.mcp.json`. Then ask, for example, "use mccode to fix the failing parser
test" or "ask mccode to review my changes".

### Codex

In `~/.codex/config.toml`:

```toml
[mcp_servers.mccode]
command = "mccode"
args = ["mcp-server"]
```

### Cursor

In `~/.cursor/mcp.json` (or `.cursor/mcp.json` in a project):

```json
{
  "mcpServers": {
    "mccode": {
      "command": "mccode",
      "args": ["mcp-server"]
    }
  }
}
```

### Other clients

Any MCP client that starts stdio servers works with command `mccode` and
argument `mcp-server`. Global options go before the subcommand
(`mccode --mode auto mcp-server`). Projects you trusted honour their
`.microclaw/project.yaml` and run their checks; untrusted projects run no
checks.
