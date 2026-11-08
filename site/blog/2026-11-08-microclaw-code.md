---
slug: /microclaw-code
title: "MicroClaw Code: a Coding Agent That Checks Its Own Work, Now at Home in Zed"
authors: [microclaw]
tags: [code, release, agents, security, runtime]
description: "MicroClaw Code (mccode) is a coding agent for your own repository. It reads, edits with visible diffs, runs your project's checks and fixes what fails, inside the OS sandbox. As of 0.27.0 it is a first-class agent in Zed's Agent Panel, and it also runs in the terminal, in scripts and CI, and as a tool for Claude Code, Codex and Cursor."
---

For most of its life MicroClaw has been a bot that lives in your chats. Over the last few releases it gained a third product next to the Server and the Rust SDK: **MicroClaw Code**, or `mccode`, a coding agent for your own repository.

You describe a change. It reads the code, edits files (every edit shown as a diff), runs commands and your project's own checks, and fixes what fails. It runs on your machine, with your toolchain, and since 0.27.0 the way we recommend using it is inside [Zed](https://zed.dev).

This post is a tour: what a task looks like, why Zed, how it stays safe, and what it can do outside an editor. MicroClaw Code is still marked **Preview**, and the last section lists what is not done yet.

{/* truncate */}

## What a task looks like

Say you ask: *"add a `--verbose` flag to the CLI and a test for it."*

1. **It looks around.** Reads, searches and globs (which respect `.gitignore`) find the CLI entry point and the existing tests. For wide questions it can start `explore` helpers: read-only sub-agents with their own context that run in parallel and come back with a short report, so your main conversation is not filled with file dumps.
2. **It edits.** Each change is a real diff with old and new text. `edit_file` refuses to overwrite a file that changed on disk since the agent last read it, and `apply_patch` changes several files at once, either all of them or none.
3. **It checks.** When the turn changed the working tree, through the file tools or through a shell command, the project's checks run: build, lint and tests. They are detected for Rust, Node, Python, Go and Makefiles, or listed in `.microclaw/project.yaml`. Language-server diagnostics (rust-analyzer, typescript-language-server, pyright, gopls) are reported as one more check.
4. **It fixes.** A failure goes back to the agent for a bounded number of fix rounds (two by default), with an explicit instruction not to weaken the tests to make them pass.
5. **You decide.** In the terminal, every turn ends with a receipt: changed files, check results, sandbox and network use, tokens, and the checkpoint. If you don't like it, `/undo` puts the files back as they were before that turn.

Step 3 is the part we care about most. An agent that edits code and then says "done" is guessing. An agent that runs your tests and reads the failures can say why it thinks the change is done.

## Why Zed

The terminal UI is good. Over 0.25.0 it gained themes, syntax-highlighted Markdown, side-by-side diffs, hunk-level review and a side panel. Still, most people review code in an editor, and Zed speaks the [Agent Client Protocol](https://agentclientprotocol.com). That lets MicroClaw Code show up in Zed's Agent Panel as its own agent, next to Zed's built-in one.

0.27.0 was mostly about making that integration good, and about testing it by hand in Zed. In the panel you get:

- **Mode and model pickers** under the message box: *Plan* (read-only, proposes a plan), *Ask* (edits apply, commands ask first) and *Auto* (commands run, destructive ones still ask).
- **Real diffs** for every edit, rendered like Zed's own agent edits.
- **Checks as cards**: `Check tests: …` with the result, followed by the fix round when a check fails.
- **Approval cards** with *Approve once*, *Always allow* the tool, *Always allow this command in this project* (for single simple commands such as `cargo test`) and *Deny*. The agent waits for your answer and continues in the same run.
- **A context ring** showing how much of the model's window the session uses, plus `/cost`, `/context`, `/compact`, `/review`, `/undo` and your own `/` commands.
- **Thread history.** Each thread is a MicroClaw Code session. Sessions started in the terminal show up too: **Import Threads** brings them in.

If no model is configured yet, Zed offers a **Set up MicroClaw Code** sign-in that runs `mccode setup` in a terminal.

## Getting started

Install `mccode`:

```sh
curl -fsSL https://microclaw.org/install-mccode.sh | bash   # macOS, Linux
brew install microclaw/tap/mccode                           # or Homebrew
```

On Windows: `iwr https://microclaw.org/install-mccode.ps1 -UseBasicParsing | iex`. The installers check the download against the release's `SHA256SUMS.txt`.

Pick a provider and a model. OpenAI, Anthropic, OpenRouter, DeepSeek, Ollama and the other providers MicroClaw supports all work:

```sh
mccode setup
mccode doctor
```

If you don't have Zed yet, it is free: [zed.dev/download](https://zed.dev/download), or `brew install --cask zed` on macOS. Then add MicroClaw Code as an agent in Zed's settings, using the path that `which mccode` prints:

```json
{
  "agent_servers": {
    "MicroClaw Code": {
      "type": "custom",
      "command": "/Users/you/.local/bin/mccode",
      "args": ["acp"]
    }
  }
}
```

Open a repository, open the Agent Panel, click **+**, choose **MicroClaw Code**, and type a task.

:::note[Version]
The Zed features in this post need `mccode` 0.27.0 or later. Check with `mccode --version`, and update with `mccode update` or `brew upgrade mccode`.
:::

The full walkthrough, including troubleshooting, is in [Use with Zed](/docs/code-editors).

## Safe by default

A coding agent runs commands on your machine, so most of the design work went into making that boring.

- **The OS sandbox.** Shell commands run under Seatbelt on macOS and bubblewrap on Linux, with a Landlock fallback when bubblewrap is missing. The root filesystem is read-only. Writes are allowed only in the repository, temp and tool caches. Credential directories such as `~/.ssh`, `~/.aws` and `~/.mccode` itself are hidden. `--no-network` cuts the network too, and with the network off, *Ask* mode can run sandboxed commands without asking. Windows has no OS sandbox, and MicroClaw Code says so: commands ask first, and *Auto* mode shows a warning.
- **Project trust.** A cloned repository can carry `.microclaw/project.yaml` with checks, hooks and instructions. None of it takes effect until you trust the project, and trust is tied to that exact file content: if the file changes, the project needs your trust again. Trusted projects also load `AGENTS.md` (or `CLAUDE.md`) into the agent's instructions.
- **Permission rules and hooks.** You can write `allow`, `ask` and `deny` rules for `bash`, `read`, `edit`, `net`, `mcp`, `agent` and `tool`, and hooks that follow the Claude Code hook protocol. They live in user, project, local and managed settings layers. They are enforced inside the engine's tool gate, so sub-agents go through them too.
- **Checkpoints.** Every turn takes a workspace checkpoint. `/undo` restores the last one, and `/rewind` (or Esc Esc in the terminal) opens a picker of earlier turns.
- **A home of its own.** Everything MicroClaw Code stores is in `~/.mccode`: the model config, sessions, memory, trust decisions and allow rules. It never reads a MicroClaw Server configuration, and a `microclaw.config.yaml` inside a repository is never loaded, so a cloned project cannot choose your model endpoint. `mccode config show` prints API keys masked, as `sk-…abcd`.

## Long sessions

Real coding sessions run long, so the context machinery was rebuilt for them in 0.23.0:

- Every request is measured against the model's context window. Compaction starts at 80% of the usable window.
- It **prunes old tool outputs first**, without a model call. A file read again replaces the earlier read.
- Only after that does older history become a **structured summary** (goal, decisions, files and state, errors and fixes, plan, next step). The summary keeps your own earlier messages word for word and lists the files changed.
- If the summarizer fails, a mechanical digest is kept instead of dropping the history.
- `/context` shows the breakdown, `/compact <focus>` compacts on demand, and `/handoff <task>` starts a fresh session from a summary aimed at the next task.

## Beyond the editor

The same agent works wherever you need it:

- **The terminal**: `mccode` opens the full-screen UI. Enter queues a message while the agent works, Ctrl+S steers the running turn, `/goal` keeps going until a condition holds and the checks pass, and `/btw` asks a side question in a copy of the session.
- **Scripts and CI**: `mccode -p "fix the failing parser test"` runs one task and exits with `0` (done), `1` (failed, or checks still failing) or `2` (an approval is pending). `--json` streams one event per line.
- **Parallel tasks**: `mccode --worktree name` runs a session in its own git worktree and branch.
- **Pull request review**: `mccode review --pr 123` reviews a PR's diff, and `--post` posts the findings as a comment.
- **Inside other agents**: `mccode mcp-server` exposes `run` and `review` as MCP tools. For Claude Code that is `claude mcp add mccode -- mccode mcp-server`, and Codex and Cursor take a few lines of config. Other ACP editors use `mccode acp` the way Zed does.
- **Away from your desk**: pair with a MicroClaw Server (`mccode remote pair`) and approval cards and "done" notifications reach you on Telegram, Discord or Slack.
- **Evaluation**: `mccode eval` runs task cases against a repository snapshot. `mccode eval replay v0.10.0..HEAD` turns real bug-fix commits into cases, so you can measure a model on your own history.

## One engine

MicroClaw Code is not a separate agent glued on. It reaches the same Agent Engine as the MicroClaw Server, and only through the public `microclaw-sdk` (CI fails if it depends on the engine directly). Tools, memory, Skills and model providers behave the same in your chat bot, in your own Rust program and in your editor. Features built for Code, such as in-run approvals, checkpoints, token-aware compaction and the OS sandbox, are available to SDK users and to the Server as well.

## What's not there yet

It is a Preview, and some gaps are known:

- Windows has no OS sandbox.
- In the terminal, Esc Esc rewinds files but not the conversation, and Ctrl+B does not send a running command to the background.
- There is no separate model for sub-agents yet (`model.roles.subagent` is not used).
- `read(...)` rules do not cover shell commands, and `net(...)` rules cover only `web_fetch`.
- MicroClaw Code is not in the ACP Registry yet, so in Zed you add it as a custom agent.

## Try it

```sh
curl -fsSL https://microclaw.org/install-mccode.sh | bash
mccode setup
```

Then open a repository in Zed, or run `mccode` in it. The [MicroClaw Code docs](/docs/code) cover everything above in detail. Bug reports and ideas are welcome on [GitHub](https://github.com/microclaw/microclaw/issues).
