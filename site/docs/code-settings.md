---
id: code-settings
title: MicroClaw Code settings
sidebar_label: Settings and customization
---

# MicroClaw Code settings

`mccode` reads one settings format from four layers. Use it for the model
and per-role models, permission rules, the sandbox's network access, hooks,
the look of the terminal interface, key bindings and notifications.

## Layers

| Layer | File | Notes |
|---|---|---|
| user | `~/.mccode/settings.yaml` | Your preferences for every project. |
| project | `<repo>/.microclaw/settings.yaml` | Shared with the repository. Read only in [trusted projects](./code-usage#project-trust). |
| local | `<repo>/.microclaw/settings.local.yaml` | This project, not committed: mccode adds it to the repository's `.git/info/exclude` when it writes the file. Read only in trusted projects. "Always allow" choices and `/permissions add` go here. |
| managed | `/etc/mccode/managed.yaml` (macOS: `/Library/Application Support/mccode/managed.yaml`) | Set by an administrator. Its values win and its `deny` / `ask` rules always apply. |

The layers merge in that order: user, then project, then local, then managed.
For a single value, the later layer wins. Lists are combined instead:
permission rules, hooks, domains, writable roots and notification events from
every layer all apply. `.microclaw/project.yaml` keeps working as before; it
holds checks, instructions and verification settings.

Editors that understand the YAML language server get completion and
validation from the schema line at the top of the file:

```yaml
# yaml-language-server: $schema=https://microclaw.ai/schema/code-settings.v1.json
version: 1
```

The schema is also in the repository (`docs/schema/code-settings.v1.json`)
and printed by `mccode config schema`. Settings files carry a `version`;
`mccode config migrate` upgrades older files when the format changes.

## Commands

```sh
mccode config                          # effective settings
mccode config get tui.theme            # one value and the layer it comes from
mccode config set tui.theme github-light
mccode config set --layer local permissions.default_mode auto
mccode config unset tui.sidebar
mccode config paths                    # files in merge order, which are loaded
mccode config doctor                   # unknown keys, bad rules, bad values
mccode config init                     # commented template (user layer)
mccode config edit --layer project     # open a layer in $EDITOR, then check it
```

In the TUI, `/config`, `/config get|set|unset|doctor|paths`, `/permissions`,
`/hooks`, `/keys` and `/theme` do the same.

You can also ask for a change in plain words. For example,
`/configure use a light theme and ask me before any git push` has the model
propose concrete changes. You see each one, with the layer it would write to,
and nothing is written until you confirm.

## Example

```yaml
# yaml-language-server: $schema=https://microclaw.ai/schema/code-settings.v1.json
version: 1

model:
  default: deepseek/deepseek-v4-pro      # <profile>/<model>
  roles:
    plan: anthropic/claude-opus-5-5      # plan-mode turns
    review: deepseek-v4-pro              # /review and mccode review
    summary: deepseek-flash              # compaction summaries and handoffs
  profiles:
    deepseek:
      type: openai                       # any OpenAI-compatible API
      base_url: https://api.deepseek.com
      api_key_env: DEEPSEEK_API_KEY
      model: deepseek-v4-pro

permissions:
  default_mode: ask
  allow:
    - bash(cargo test *)
    - bash(git status)
    - edit(src/**)
  ask:
    - bash(git push *)
    - mcp(github.*)
  deny:
    - read(**/.env)
    - bash(rm -rf /*)

sandbox:
  network: ask                           # off | ask | on
  allow_domains: [docs.rs, crates.io, "*.github.com"]

hooks:
  pre_tool_use:
    - matcher: Bash
      command: ./scripts/guard.sh
  post_edit:
    - matcher: Edit|Write
      command: cargo fmt -- {file}

tui:
  theme: auto
  screen: auto                           # auto | fullscreen | inline
  sidebar: auto                          # auto | show | hide
  diff: auto                             # auto | split | unified
  status_line: [mode, model, context, tokens, cost, branch]
  notifications: { method: auto, when: unfocused }
  keymap:
    chat.steer: ctrl+s

notify:
  chat: telegram:123456789
  events: [approval, done, check_failed]
```

## Models

`model.profiles` lets MicroClaw Code reach a provider without a full
MicroClaw configuration file. If `model.default` names a profile (and
`--config` is not given), that profile is used instead of `config.yaml`. Keep
API keys in environment variables (`api_key_env`), or put `api_key` in the
user layer only; `mccode config doctor` warns about keys in project layers.

`model.roles` picks models for kinds of work: `plan` for plan-mode turns,
`review` for reviews, `summary` for compaction summaries and handoffs. A role
switches the model within the session's provider, so it must name a model on
the same profile (`ds/deepseek-v4-pro` when the session runs on `ds`) or a bare
model name; a role on another profile is skipped with a warning. Unset roles
use the session's model.
`/model` opens a picker with your profiles and the built-in presets, which
list each model's context window.

## Permission rules

A rule is `<kind>(<pattern>)`:

| Kind | Matches | Pattern |
|---|---|---|
| `bash` | shell commands | Command text; `*` is a wildcard and `git push` also matches `git push origin main`. Commands joined with `&&`, `\|\|`, `;`, `\|` are checked one by one: a deny or ask on any part applies, and an allow needs every part to be allowed. |
| `read` | `read_file`, `glob`, `grep` | Path glob relative to the project (`src/**`, `**/.env`); absolute and `~/` paths work. |
| `edit` | `write_file`, `edit_file`, `apply_patch` | Path glob, checked against every file a patch touches. |
| `net` | `web_fetch` | Host, with `*.example.com` wildcards. |
| `mcp` | MCP tools | `server.tool` glob. |
| `agent` | `explore`, sub-agents | Agent name. |
| `tool` | any tool | Tool name glob. |

Deny wins over ask, and ask wins over allow.

- **`deny`** blocks the call and tells the model why.
- **`ask`** needs your approval, even for tools that normally run without one, and even in auto mode.
- **`allow`** lets shell commands run without asking.

Edits outside the project always ask unless an allow rule covers them.
Claude Code spellings are accepted too: `Bash(npm test)`, `Read(./.env)`,
`Edit(src/**)`, `WebFetch(domain:docs.rs)`, `mcp__github__create_issue`.

`sandbox.network` controls web access for both shell commands and web tools:

| Value | Shell commands | Web tools |
|---|---|---|
| `on` | Have network access. | Run without asking. |
| `ask` | Run without network. | Ask for any host not listed in `allow_domains`. |
| `off` | Run without network. | Are denied for any host not listed in `allow_domains`. |

## Hooks

Hooks use the Claude Code protocol, so existing hook scripts work as they
are.

- **Input:** the event arrives as JSON on stdin, with `session_id`, `cwd`,
  `hook_event_name`, `tool_name` and `tool_input`. Tool names use the Claude
  spelling (`Bash`, `Edit`, `Read`, …), and `microclaw_tool_name` holds ours.
- **Blocking:** exit code 2 blocks, with stderr as the reason.
- **JSON output:** on stdout, a hook can return `decision`, `reason`,
  `hookSpecificOutput.permissionDecision` (`allow` / `ask` / `deny`),
  `updatedInput`, `additionalContext`, `continue` and `systemMessage`.
- **HTTP:** set `url` instead of `command` to POST the same JSON to an
  endpoint and read the same JSON back.

| Event | When | Can |
|---|---|---|
| `session_start` / `session_end` | The TUI starts or exits | Show messages |
| `user_prompt_submit` | Before a prompt is sent | Block it, add context |
| `pre_tool_use` | Before every tool call, sub-agents included | Allow, ask, deny, rewrite the input |
| `post_tool_use` | After every tool call | Add context to the result |
| `post_edit` | After each edited file (`{file}` in the command) | Format the file, add context |
| `permission_request` | When an approval would be shown | Approve or deny it |
| `notification` | When MicroClaw Code needs you | Forward the notification |
| `pre_compact` | Before `/compact` | Block it |
| `stop` | When a turn ends | Block, which sends the reason back to the agent once |

Each handler can set a `matcher`, a regex on the tool name (either spelling),
and a `timeout` in seconds (default 60). The older `hooks.after_edit` and
`hooks.after_turn` in `project.yaml` still run.

## Look and feel

**Themes.**
- **Built in:** `dark`, `light`, `ansi` (only the 16 terminal colours),
  `tokyonight`, `catppuccin`, `gruvbox`, `nord`, `dracula`, `one-dark`,
  `solarized-light`, `github-light`.
- **`auto`:** chooses dark or light from the terminal's background (via
  `COLORFGBG`) and defaults to dark.
- **Colour depth:** on 256-colour terminals colours are mapped to the nearest
  palette entry. On 16-colour terminals, or with `NO_COLOR`, the `ansi` theme
  is used.
- **Picking one:** `/theme` previews themes live as you move through the list
  and saves your choice to the user layer.

**Custom themes.** Put YAML files in `~/.mccode/themes/`.
OpenCode theme JSON files work in the same directory.

```yaml
name: my-theme
base: dark                 # tokens not set here come from the base
palette:
  blue: "#7aa2f7"
tokens:
  accent: blue
  background_panel: "#1f2335"
  diff_added_bg: "#20303b"
  diff_removed_bg: "#37222c"
  mode_auto: { dark: "#e0af68", light: "#8f5e15" }
  syntax_theme: Coldark-Dark
```

A token value is one of: `#rrggbb`, a 0–255 palette index, a palette name,
`{dark, light}`, or `none` (use the terminal's own colour).

**Screen.** `screen: fullscreen` uses the alternate screen and has mouse
support:

- The wheel scrolls.
- Clicking a tool call expands it.
- Shift-drag selects text in most terminals.

`screen: inline` writes finished output into the terminal's own scrollback
and redraws only the bottom of the screen. `auto` chooses inline under
Zellij and fullscreen otherwise. If a terminal cannot run inline mode,
`mccode` falls back to fullscreen.

**Other options:**
- `sidebar`: the side panel (plan, checks, changed files, sub-agents) shows
  on terminals 130 columns or wider.
- `diff: auto`: diffs are shown side by side from 160 columns.
- `animations: false`: stops the shimmer effects.
- `status_line`: picks and orders the idle status line from `mode`, `model`,
  `context`, `tokens`, `cost`, `branch`, `sandbox`, `session` and `checks`.

## Key bindings

`tui.keymap` maps an action to one or more keys (`ctrl+s`, `alt+enter`,
`f2`, comma-separated), or to `none`. `/keys` lists the current bindings.

| Action | Default | |
|---|---|---|
| `chat.steer` | Ctrl+S | send now as guidance to the running turn |
| `chat.newline` | Alt+Enter, Shift+Enter, Ctrl+J | new line |
| `chat.editor` | Ctrl+G | edit the prompt in `$EDITOR` |
| `chat.paste_image` | Ctrl+V | attach the clipboard image |
| `history.search` | Ctrl+R | search earlier prompts |
| `app.palette` | Ctrl+P | command palette |
| `app.mode` | Shift+Tab | plan → ask → auto |
| `app.sidebar` | Ctrl+B | show / hide the side panel |
| `app.changes` | F2 | review changes hunk by hunk |
| `app.clear` | Ctrl+L | clear the screen |
| `transcript.pager` | Ctrl+T | whole transcript with search |
| `transcript.expand` | Ctrl+O | expand all tool output and diffs |

## Notifications

**In the terminal.** When the terminal is not focused, `mccode` notifies
you on three events: an approval is needed, a turn finished, or checks
still fail.

| Setting | Values |
|---|---|
| `tui.notifications.method` | `auto` (the default), `osc9`, `osc777`, `bell`, `off`. `auto` uses OSC 9 for iTerm2, WezTerm, Ghostty and kitty, OSC 777 for VTE terminals, and the bell elsewhere. |
| `tui.notifications.when` | `unfocused` (the default) or `always`. |

These notifications are passed through tmux.

**In your chat app.** If this machine is paired with a MicroClaw Server
(`mccode remote pair`), `notify.chat` sends approvals and notifications to a
Telegram, Discord, Slack or Feishu chat.

- **Approval cards:** once the terminal has been idle for
  `after_idle_secs` (default 60), an open approval is also sent to the chat
  as a card with buttons. Answer in the chat or in the terminal; whichever
  comes first wins. Approval cards go only to the Server's control chats.
- **Other events:** `done`, `check_failed` and `error` send a short message.

See [Run tasks on a MicroClaw Server](./code-remote).

## Importing from other agents

```sh
mccode import claude                  # dry run: what would be imported
mccode import claude --apply          # into .microclaw/settings.yaml
mccode import codex --apply --target user
mccode import opencode --apply
```

| Source | What is imported |
|---|---|
| Claude Code | Permission rules and command hooks from `~/.claude/settings.json` and `.claude/settings*.json`, plus `.claude/commands`, `.claude/agents` and the servers in `.mcp.json`. |
| Codex | `mcp_servers` and simple `prefix_rule`s from `~/.codex/rules/*.rules`, plus `~/.codex/prompts`. |
| OpenCode | The `permission` map, `command`s, agents, MCP servers and themes. |

Secrets are never copied into project layers. Anything that cannot be
converted is listed as skipped. In the TUI, use
`/import claude|codex|opencode [apply]`.
