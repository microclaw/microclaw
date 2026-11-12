---
id: code
title: MicroClaw Code
sidebar_label: Overview and install
---

# MicroClaw Code (`mccode`)

MicroClaw Code is a coding agent for your own repository. You describe a
change; it reads the code, edits files (showing every diff), runs commands
and your project's checks, and fixes what fails. It runs on your machine,
with your toolchain.

**We recommend using it in [Zed](https://zed.dev)**: MicroClaw Code appears
in Zed's Agent Panel next to Zed's own agent, with diffs you can review in the
editor, approval cards, mode and model pickers and a context meter. The
same agent also runs in your terminal, with a full-screen interface or
`mccode -p` for scripts and CI. Both use the same sessions and settings.

- **In Zed** through the Agent Client Protocol: edits as real diffs, checks
  as cards, `/` commands, thread history ([set up](./code-editors)).
- **In the terminal**: a full-screen UI with streamed replies, coloured
  diffs, plans and approval dialogs, or **`mccode -p`** for scripts and CI.
- **Three permission modes**: `plan` (read-only, proposes a plan), `ask`
  (edits apply, shell commands ask first), `auto` (commands run, destructive
  ones still ask).
- **Verification built in**: after a change it runs your build, lint and
  test commands and hands failures back to the agent.
- **Safety by default**: shell commands run in the operating system's
  sandbox, edits are checkpointed (`/undo`), and project settings only take
  effect after you trust the project.
- **Works with other agents too**: any Agent Client Protocol editor through
  [`mccode acp`](./code-editors), and Claude Code, Codex, Cursor and other
  MCP clients through `mccode mcp-server`.
- **One engine**: the same Agent Engine as MicroClaw Server and the Rust SDK,
  so tools, memory, Skills and model providers behave the same everywhere.

Status: **Preview**.

## Install

### Install script (macOS, Linux)

```sh
curl -fsSL https://microclaw.org/install-mccode.sh | bash
```

The script downloads `mccode` for your platform from the latest GitHub
release, verifies it against the release's `SHA256SUMS.txt`, and installs it
to `/usr/local/bin` (or `~/.local/bin` when that is not writable). Options:

```sh
curl -fsSL https://microclaw.org/install-mccode.sh | bash -s -- --version 0.30.0
curl -fsSL https://microclaw.org/install-mccode.sh | bash -s -- --dir ~/bin
```

### Install script (Windows)

```powershell
iwr https://microclaw.org/install-mccode.ps1 -UseBasicParsing | iex
```

This installs `mccode.exe` to `%USERPROFILE%\.local\bin` and adds that folder
to your user `PATH`.

### Homebrew (macOS)

```sh
brew install microclaw/tap/mccode
```

### From source

Needs the Rust toolchain:

```sh
cargo install --git https://github.com/microclaw/microclaw microclaw-code
```

Releases before 0.25.0 have no `mccode` archives; asked for one of those, the
installers print this command instead.

### Update and uninstall

```sh
mccode update           # install the latest release (checksum-verified)
mccode update --check   # only report whether a newer release exists
```

Homebrew installs update with `brew upgrade mccode`. To uninstall, delete the
`mccode` binary (and `~/.mccode` to remove settings and sessions).

## Configure a model

```sh
mccode setup
```

`setup` asks for a provider (OpenAI, Anthropic, OpenRouter, DeepSeek, Ollama
and the other providers MicroClaw supports), a model and an API key, and
writes `~/.mccode/config.yaml` (readable only by you). For scripts:

```sh
mccode setup --provider anthropic --model claude-sonnet-4-5 --api-key "$ANTHROPIC_API_KEY"
mccode setup --provider ollama --model qwen3-coder --base-url http://127.0.0.1:11434/v1
```

A model profile in `~/.mccode/settings.yaml` works instead of that file (see
[settings](./code-settings.md)), and `--config <PATH>` or `MCCODE_CONFIG`
names another configuration file. `mccode` never uses a MicroClaw Server
configuration, and a `microclaw.config.yaml` inside a repository is never
loaded, so a cloned project cannot choose your model endpoint.

Check everything with:

```sh
mccode doctor
```

## Use it in Zed (recommended)

1. Install Zed, a free, open-source editor. Download it from
   [zed.dev/download](https://zed.dev/download), or use your package manager:

   ```sh
   brew install --cask zed                     # macOS (12 or later)
   curl -f https://zed.dev/install.sh | sh     # Linux (needs a Vulkan 1.3 driver)
   winget install -e --id ZedIndustries.Zed    # Windows (10 version 1903 or later, 64-bit)
   ```

2. Find where `mccode` is installed:

   ```sh
   which mccode     # for example /Users/you/.local/bin/mccode
   ```

3. In Zed, open the command palette (Cmd+Shift+P on macOS, Ctrl+Shift+P
   elsewhere), run `zed: open settings` and add MicroClaw Code as an agent,
   using that path:

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

4. Open your repository in Zed, open the Agent Panel, click **+** and choose
   **MicroClaw Code**. Type a task, mention files with `@`, and approve
   commands on the cards that appear.

The Zed integration described in these docs (mode and model pickers, real
diffs, permission cards, thread history) needs `mccode` 0.27.0 or later;
check with `mccode --version` and update with `mccode update`.

For trusting a project, the options above, what each part of the panel
shows and troubleshooting, see [Use with Zed](./code-editors).

## In the terminal

```sh
cd path/to/your/repo
mccode
```

1. If the repository has a `.microclaw/project.yaml` or detectable checks,
   `mccode` asks whether you **trust** it. Trusting lets the project's
   settings and checks run; you can change it later with `/trust`.
2. Type a task, for example `add a --verbose flag to the CLI and a test for
   it`. Mention files with `@path` (Tab completes them).
3. Watch the agent read, edit (each change is shown as a diff) and run
   commands. In `ask` mode a shell command opens an approval dialog: `1`
   approve once, `2` always allow the tool, `p` always allow that command in
   this project, `3` deny.
4. After the change, your project's checks run automatically; failures go
   back to the agent for a bounded number of fix rounds.
5. Not happy? `/undo` restores the files to before that turn. `/review`
   asks for a review of everything uncommitted.

Start with `/plan <task>` to get a plan first, and Shift+Tab to switch
between `plan`, `ask` and `auto`.

One task without the full-screen interface:

```sh
mccode -p "fix the failing parser test"
```

## Where things live

Everything MicroClaw Code stores is in `~/.mccode` (override with
`MCCODE_HOME`): the model configuration, the engine database and
memory, checkpoints, the session index, trust decisions and allow rules.

MicroClaw Code and the MicroClaw Server are separate products: each installs,
updates and uninstalls on its own, and neither reads the other's
configuration, data or environment variables. Pairing with a Server
(`mccode remote pair`) is the only link, and only when you set it up.

## Next

- [Use with Zed](./code-editors): the full Zed guide, other ACP editors, and
  MCP clients such as Claude Code, Codex and Cursor.
- [Using MicroClaw Code](./code-usage): modes, approvals, the sandbox,
  verification, sessions, scripting and evaluation.
- [Run tasks on a MicroClaw Server](./code-remote).
