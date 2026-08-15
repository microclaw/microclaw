---
id: usage
title: Usage Manual
sidebar_position: 5
---

A complete guide to using MicroClaw. Each section includes exact messages you can send to test the corresponding feature.

## Local Web UI

When `web_enabled: true`, MicroClaw serves a local Web UI (default `http://127.0.0.1:10961`).

- Session list shows all channels found in SQLite (`telegram`, `discord`, `slack`, `feishu`, `irc`, `web`)
- You can review chat history and manage state (refresh / clear context / delete)
- Non-web channels are read-only in Web UI by default; send from source channel
- If there are no sessions yet, Web UI auto-generates a key like `session-YYYYMMDDHHmmss`
- The first message in that session automatically persists it in SQLite

For operator endpoints (auth/session/metrics/self-check), see [Web Operator API](./web-operator-api).

## ACP Stdio Mode

If you want to use MicroClaw as a local ACP backend instead of a chat adapter, run:

```sh
microclaw acp
```

This is useful for editor integrations or local tools that already speak ACP over stdio.

For setup and validation details, see [ACP Stdio Mode](./acp).

---

## Basics

### Private chat

In a private chat with the bot, every text message triggers a response. Just open a conversation and type.

```
You: Hello
Bot: Hi! How can I help you today?
```

### Group chat

In a group, the bot only responds when you @mention it. All messages are still stored for context.
Slash commands follow the same default gate in groups/channels: mention is required unless `allow_group_slash_without_mention` is enabled.

```
Alice: I updated the config
Bob: @microclaw summarize what happened
Bot: Alice updated the config...
```

---

## Bot Commands

See [Slash Commands](./commands) for the complete, up-to-date list and behavior.

Operational behavior:
- Any message starting with `/` is treated as a command.
- Mention-prefixed slash is supported (for example `@bot /status`, `<@U123> /status`).
- Slash commands are handled out-of-band and do not enter agent conversation history.
- Unknown slash commands return `Unknown command.`.
- `/stop` aborts only the current in-flight run; use `/reset` if you need to clear context.
- `/provider` and `/model` update the current bot/account override and persist it to `microclaw.config.yaml`.

## Plugins

MicroClaw supports manifest-based plugins for slash commands, dynamic tools, and context providers.

- Plugin docs: [Plugins](./plugins)
- Control chat admin commands: `/plugins list`, `/plugins validate`, `/plugins reload`

---

## Conversation Archive

MicroClaw can archive full conversations to markdown files for later reference.

**Automatic**: When context compaction triggers (session exceeds `max_session_messages`), the full conversation is automatically archived before being summarized.

**Manual**: Send `/archive` to save the current session on demand, without clearing or compacting it.

Archives are stored at:

```
~/.microclaw/runtime/groups/<channel>/<chat_id>/conversations/<YYYYMMDD-HHMMSS>.md
```

Each message is saved with its role (user/assistant) and full content including tool calls and results.

```
You: /archive
Bot: Archived 42 messages.
```

---

## Shell Commands (bash)

Run any shell command on the host machine. The bot returns stdout, stderr, and exit code.

```
You: Run `uname -a` for me
Bot: [executes bash, returns system info]
```

```
You: List all files in the current directory
Bot: [runs ls, returns file listing]
```

```
You: Run `echo hello && sleep 2 && echo done`
Bot: hello
     done
```

**Timeout**: Default 120 seconds. LLM can set a custom timeout for long-running commands.

**Output truncation**: Output longer than 30,000 characters is truncated.

---

## File Operations

### Read a file

Reads file content with line numbers. Supports offset and limit for large files.

```
You: Read the file /etc/hosts
Bot: [displays file with line numbers]
```

```
You: Show me lines 10-20 of /var/log/system.log
Bot: [displays lines 10-20 with line numbers]
```

### Write a file

Creates or overwrites a file. Automatically creates parent directories.

```
You: Create a file /tmp/hello.txt with the content "Hello, World!"
Bot: Successfully wrote to /tmp/hello.txt
```

```
You: Write a Python script to /tmp/greet.py that prints "Hello from MicroClaw"
Bot: [writes the script]
```

### Edit a file

Finds an exact string in a file and replaces it. The old string must appear exactly once.

```
You: In /tmp/hello.txt, change "World" to "MicroClaw"
Bot: Successfully edited /tmp/hello.txt
```

```
You: In /tmp/greet.py, replace the print message with "Goodbye"
Bot: [edits the file]
```

---

## File Search

### Glob (find files by pattern)

Finds files matching a glob pattern. Supports `**` for recursive matching.

```
You: Find all .rs files in the current directory
Bot: [lists matching files]
```

```
You: Search for files matching **/*.toml
Bot: [lists all .toml files recursively]
```

### Grep (search file contents)

Searches file contents with regex patterns. Returns matching lines with file paths and line numbers.

```
You: Search for "TODO" in all files in the current directory
Bot: [shows matching lines with file:line format]
```

```
You: Find all occurrences of "fn main" in .rs files
Bot: [searches with glob filter *.rs]
```

---

## Web Search

Searches the web via DuckDuckGo. Returns titles, URLs, and snippets for the top 8 results.

```
You: Search the web for "Rust async programming best practices"
Bot: 1. Title...
     URL...
     Snippet...

     2. Title...
     ...
```

```
You: What's the latest news about Anthropic?
Bot: [searches and summarizes results]
```

---

## Web Fetch

Fetches a URL and returns plain text (HTML tags stripped). Maximum 20KB.

```
You: Fetch https://example.com and tell me what it says
Bot: [fetches page, strips HTML, returns text content]
```

```
You: Go to https://httpbin.org/get and show me the response
Bot: [fetches and displays the JSON response]
```

---

## Memory System

MicroClaw has persistent memory stored in `AGENTS.md` files, plus structured memory rows in SQLite.

AGENTS.md scopes:

- **Global memory**: Shared across all chats (`~/.microclaw/runtime/groups/AGENTS.md`)
- **Bot memory**: Shared by one bot/account within a channel (`~/.microclaw/runtime/groups/{channel}/AGENTS.md`)
- **Chat memory**: Specific to one chat, namespaced by channel (`~/.microclaw/runtime/groups/{channel}/{chat_id}/AGENTS.md`)

Memory is automatically injected into the system prompt on every request.
Structured memory is also injected with a token budget and relevance ranking.

## Session-Native Subagents

MicroClaw supports asynchronous sub-agent runs with durable IDs and lifecycle state.

Typical operator flow:

1. ask the agent to spawn delegated work
2. inspect progress with `subagents_list` or `subagents_info`
3. continue a focused run with `subagents_send`
4. cancel stale work with `subagents_kill`

Runs can execute on the native MicroClaw runtime or on an ACP-backed external worker. For structured clients that call `sessions_spawn` directly, pass `runtime: "acp"` and optionally `runtime_target` to choose a named ACP worker.

```json
{
  "task": "Review the repo and summarize risky files",
  "runtime": "acp",
  "runtime_target": "reviewer"
}
```

Behavior notes:

- if `runtime_target` is omitted, MicroClaw resolves the target from `subagents.acp.default_target`, the inline ACP worker, or the only enabled named target
- `subagents_send` keeps the same runtime and target when you continue a focused ACP run
- `subagents_log` includes ACP permission, plan, tool-call, file, and terminal events for external runs

If long-running subagent tasks fail with `budget_exceeded`, increase:

```yaml
subagents:
  max_tokens_per_run: 240000
  run_timeout_secs: 1800
```

Use the generated tools reference or [Tools Reference](./tools) for the exact tool names.

### Write memory

```
You: Remember that my preferred programming language is Rust
Bot: Noted. Saved memory #123: my preferred programming language is Rust
```

```
You: Save to global memory: The production server IP is 10.0.1.50
Bot: Memory saved to global scope.
```

### Manage structured memories

```
You: Search memory for "production database"
Bot: [id=42] [KNOWLEDGE] [chat] production database is on port 5433
```

```
You: Update memory id 42 to "production database is on port 6432"
Bot: Memory id=42 updated.
```

```
You: Delete memory id 42
Bot: Memory id=42 archived.
```

### Read memory

```
You: What do you remember about me?
Bot: [reads memory and responds with stored info]
```

```
You: Show me your global memory
Bot: [reads and displays AGENTS.md content]
```

### Memory persists across conversations

```
[Session 1]
You: Remember that the deploy key is in /home/deploy/.ssh/id_ed25519

[Session 2 — hours or days later]
You: Where's the deploy key?
Bot: The deploy key is in /home/deploy/.ssh/id_ed25519
```

---

## Usage Panel: Memory Observability

Open **Usage Panel** from the sidebar. In addition to token usage, it now shows:

- Memory Pool: total / active / archived
- Average confidence + low-confidence count
- Reflector 24h throughput: inserted / updated / skipped
- Injection coverage: selected / candidate memories

Use this panel to tune `reflector_interval_mins`, `memory_token_budget`, and semantic-memory config.

---

## Agent Skills

MicroClaw auto-discovers local skills from `~/.microclaw/skills/*/SKILL.md`.  
Use `/skills` in chat to list all available skills.

See the dedicated skills reference for per-skill details: [Skills](./skills).

Built-in examples now include:

- `apple-notes` (macOS Apple Notes via `memo`)
- `apple-reminders` (macOS Apple Reminders via `remindctl`)
- `apple-calendar` (macOS Calendar via `icalBuddy` + `osascript`)
- `weather` (quick weather lookup via `wttr.in`)

If a request matches a skill, the model can call `activate_skill` and then follow that skill's detailed workflow.

---

## Bot Personality (SOUL.md)

MicroClaw supports a `SOUL.md` file that defines the bot's personality, voice, values, and working style. When present, the file content replaces the default "helpful AI assistant" identity in the system prompt.

### How it loads

MicroClaw checks for a soul file in this order (first match wins):

1. `channels.<caller>.accounts.<id>.soul_path` (when request is routed through a specific channel account)
2. `channels.<caller>.soul_path` (channel-level fallback)
3. `soul_path` in config (global explicit path)
4. `<data_dir>/SOUL.md`
5. `./SOUL.md` (project root)

A default `SOUL.md` ships with the repo.

Notes:
- For bare channel callers (for example `telegram`), MicroClaw first checks that channel's `default_account` (if configured) for account-level `soul_path`.
- Per-chat soul override still has highest priority and fully overrides all global/channel/account soul settings.

### Per-chat personality

Place a `SOUL.md` at `<data_dir>/runtime/groups/<chat_id>/SOUL.md` to give a specific chat a different personality. The per-chat file fully overrides the global soul for that chat.

### Example

```markdown
# Soul

I am a capable, action-oriented AI assistant.

## Personality
- I prefer doing over discussing.
- I have a dry sense of humor.
- I'm optimistic by default. Problems are puzzles, errors are clues.

## Values
- Reliability over impressiveness.
- Transparency — if something fails, I say so plainly.

## Working style
- I report outcomes, not intentions — "done" beats "I'll try".
```

### Config

```yaml
# Optional: explicit path (otherwise auto-discovered)
soul_path: "./SOUL.md"
```

---

## Mid-Conversation Messaging (send_message)

LLM can send messages to the chat during tool execution, useful for progress updates on long tasks.

```
You: Analyze all log files in /var/log and give me a summary
Bot: [sends "Scanning log files..." as a progress update]
Bot: [sends "Found 15 log files, analyzing..." as another update]
Bot: [final summary response]
```

You don't need to explicitly ask for this. LLM uses it automatically when working on multi-step tasks.

Permission note: cross-chat `send_message` is allowed only for chats listed in `control_chat_ids`.

---

## Scheduling

MicroClaw has a background scheduler that polls every 60 seconds.

Permission note: scheduling/listing/managing tasks for another chat is allowed only for `control_chat_ids`.

### Schedule a recurring task (cron)

Uses 6-field cron format: `sec min hour dom month dow`

```
You: Every 5 minutes, tell me a random fun fact
Bot: Task #1 scheduled. Next run: 2025-06-15T12:05:00+00:00
```

```
You: Schedule a daily task at 9am UTC to check https://news.ycombinator.com and summarize the top 3 stories
Bot: Task #2 scheduled. Next run: 2025-06-16T09:00:00+00:00
```

Common cron patterns:
| Pattern | Meaning |
|---|---|
| `0 */5 * * * *` | Every 5 minutes |
| `0 0 * * * *` | Every hour |
| `0 0 9 * * *` | Daily at 9:00 AM |
| `0 0 9 * * 1-5` | Weekdays at 9:00 AM |
| `0 30 */2 * * *` | Every 2 hours at :30 |

### Schedule a one-time task

```
You: At 2025-12-31T23:59:00+00:00, send me a New Year countdown message
Bot: Task #3 scheduled. Next run: 2025-12-31T23:59:00+00:00
```

### List scheduled tasks

```
You: List my scheduled tasks
Bot: #1 [active] tell a fun fact | cron '0 */5 * * * *' | next: ...
     #2 [active] check HN | cron '0 0 9 * * *' | next: ...
```

### Pause / Resume / Cancel tasks

```
You: Pause task #1
Bot: Task #1 paused.

You: Resume task #1
Bot: Task #1 resumed.

You: Cancel task #2
Bot: Task #2 cancelled.
```

---

## Group Chat Catch-up

In group chats, when someone @mentions the bot, it loads all messages since its last reply for full context.

```
Alice: We need to migrate from PostgreSQL to MySQL
Bob: I think we should also update the ORM
Charlie: Let's use SQLAlchemy
Dave: @microclaw What do you think about this migration plan?

Bot: [has full context of Alice, Bob, and Charlie's messages]
     Based on your discussion, here's my take on the migration...
```

---

## Long Response Splitting

chat has a 4096-character message limit. MicroClaw automatically splits long responses at newline boundaries.

```
You: Give me a detailed explanation of the Rust ownership system with examples
Bot: [message 1 — first ~4096 chars, split at a newline]
Bot: [message 2 — remaining content]
```

---

## Typing Indicator

While processing your message (calling LLM API, executing tools), the bot shows a "typing..." indicator in the chat. The indicator refreshes every 4 seconds until the response is ready.

---

## Combined Workflows

MicroClaw chains tools automatically. A single message can trigger multiple tool calls.

### Code review

```
You: Read the file src/main.rs, find any potential issues, and write a summary to /tmp/review.txt
Bot: [reads file -> analyzes -> writes summary -> reports back]
```

### Research + save

```
You: Search for the latest Rust async runtime benchmarks, fetch the most relevant page, and save a summary to global memory
Bot: [web_search -> web_fetch -> write_memory -> responds with summary]
```

### Deploy check

```
You: Check if port 8080 is in use, read the nginx config, and tell me if everything looks correct
Bot: [bash: lsof -i :8080 -> read_file: /etc/nginx/nginx.conf -> analysis]
```

---

## CLI Reference

```sh
microclaw start       # Start the bot
microclaw setup      # Interactive setup wizard
microclaw doctor      # Cross-platform preflight diagnostics
microclaw doctor --json # Machine-readable diagnostic output
microclaw web         # Show Web password command usage
microclaw web password <value> # Set Web UI operator password
microclaw web password-generate # Generate and set a random Web UI operator password
microclaw web password-clear # Clear password hash + revoke sessions
microclaw setup       # Full-screen setup wizard
microclaw gateway install # Install + enable persistent gateway service
microclaw gateway install --force # Reinstall service files and restart
microclaw gateway status  # Show gateway service status
microclaw gateway status --json --deep # Structured status + platform detail
microclaw gateway restart # Restart gateway service
microclaw gateway stop    # Stop gateway service
microclaw gateway logs 200 # Show recent runtime logs
microclaw gateway uninstall # Remove gateway service
microclaw help        # Show help and all configuration options
```

### Config Keys

| Key | Required | Default | Description |
|---|---|---|---|
| `channels.telegram.accounts.<id>.bot_token` | Yes (when Telegram enabled) | - | Telegram bot token per account |
| `channels.discord.accounts.<id>.bot_token` | Yes (when Discord enabled) | - | Discord bot token per account |
| `channels.slack.accounts.<id>.bot_token` | Yes (when Slack enabled) | - | Slack bot token per account |
| `channels.slack.accounts.<id>.app_token` | Yes (when Slack enabled) | - | Slack app token (Socket Mode) per account |
| `channels.feishu.accounts.<id>.app_id` | Yes (when Feishu/Lark enabled) | - | Feishu/Lark app ID per account |
| `channels.feishu.accounts.<id>.app_secret` | Yes (when Feishu/Lark enabled) | - | Feishu/Lark app secret per account |
| `channels.feishu.accounts.<id>.topic_mode` | No | `false` | Optional per-bot threaded reply mode; only supported when account domain is `feishu` or `lark` |
| `api_key` | Yes* | - | LLM API key (`ollama` can leave this empty; `openai-codex` supports OAuth or `api_key`) |
| `bot_username` | Yes* | - | Global default bot username |
| `channels.telegram.default_account` | No | unset | Default Telegram account ID in multi-account mode |
| `channels.telegram.accounts.<id>.bot_username` | No | unset | Per-account Telegram username (without `@`) |
| `channels.telegram.topic_routing.enabled` | No | `false` | Route Telegram forum topics as isolated chats (`external_chat_id=<chat_id>:<thread_id>`) |
| `channels.telegram.accounts.<id>.topic_routing.enabled` | No | inherit channel-level | Optional per-account override for Telegram topic routing |
| `model` | No | provider-specific (`claude-sonnet-4-5-20250929` for `anthropic`) | LLM model ID |
| `data_dir` | No | `~/.microclaw` | Data root (`runtime` data in `data_dir/runtime`, skills in `data_dir/skills`) |
| `working_dir` | No | `~/.microclaw/working_dir` | Default working directory for `bash/read_file/write_file/edit_file/glob/grep`; relative paths resolve from here |
| `override_timezone` | No | unset | Optional IANA timezone override. By default MicroClaw uses detected system timezone; when set, this value takes precedence. |
| `max_tokens` | No | `8192` | Max tokens per response |
| `max_tool_iterations` | No | `100` | Max tool loop iterations |
| `max_document_size_mb` | No | `100` | Max inbound Telegram document size (MB); larger files are rejected |
| `max_history_messages` | No | `50` | Chat history context size |
`*` `bot_username` can be overridden per channel with optional `channels.<name>.bot_username` and, in multi-account mode, `channels.<name>.accounts.<id>.bot_username`.
