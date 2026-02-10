# MicroClaw
<img src="icon.png" alt="MicroClaw logo" width="56" align="right" />

[English](README.md) | [中文](README_CN.md)

[![Website](https://img.shields.io/badge/Website-microclaw.ai-blue)](https://microclaw.ai)
[![Discord](https://img.shields.io/badge/Discord-Join-5865F2?logo=discord&logoColor=white)](https://discord.gg/pvmezwkAk5)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **Note:** This project is under active development. Features may change, and contributions are welcome!

<p align="center">
  <img src="screenshots/screenshot1.png" width="45%" />
  &nbsp;&nbsp;
  <img src="screenshots/screenshot2.png" width="45%" />
</p>

An agentic AI assistant for chat surfaces, inspired by [nanoclaw](https://github.com/gavrielc/nanoclaw/) and incorporating some of its design ideas. MicroClaw is Telegram-first (with optional WhatsApp Cloud API webhook support) and works with multiple LLM providers (Anthropic + OpenAI-compatible APIs). It supports full tool execution: run shell commands, read/write/edit files, search codebases, browse the web, schedule tasks, and maintain persistent memory across conversations.

## How it works

```
Chat message (Telegram / WhatsApp)
    |
    v
 Store in SQLite --> Load chat history + memory
                         |
                         v
               Selected LLM API (with tools)
                         |
                    stop_reason?
                   /            \
              end_turn        tool_use
                 |               |
                 v               v
           Send reply      Execute tool(s)
                              |
                              v
                        Feed results back
                        to model (loop)
```

Every message triggers an **agentic loop**: the model can call tools, inspect the results, call more tools, and reason through multi-step tasks before responding. Up to 100 iterations per request by default.

## Blog post

For a deeper dive into the architecture and design decisions, read: **[Building MicroClaw: An Agentic AI Assistant in Rust That Lives in Your Chats](https://microclaw.ai/blog/building-microclaw)**

## Features

- **Agentic tool use** -- bash commands, file read/write/edit, glob search, regex grep, persistent memory
- **Session resume** -- full conversation state (including tool interactions) persisted between messages; the agent keeps tool-call state across invocations
- **Context compaction** -- when sessions grow too large, older messages are automatically summarized to stay within context limits
- **Sub-agent** -- delegate self-contained sub-tasks to a parallel agent with restricted tools
- **Agent skills** -- extensible skill system ([Anthropic Skills](https://github.com/anthropics/skills) compatible); skills are auto-discovered from `microclaw.data/skills/` and activated on demand
- **Plan & execute** -- todo list tools for breaking down complex tasks, tracking progress step by step
- **Web search** -- search the web via DuckDuckGo and fetch/parse web pages
- **Scheduled tasks** -- cron-based recurring tasks and one-time scheduled tasks, managed through natural language
- **Mid-conversation messaging** -- the agent can send intermediate messages before its final response
- **Group chat catch-up** -- when mentioned in a group, the bot reads all messages since its last reply (not just the last N)
- **Continuous typing indicator** -- typing indicator stays active for the full duration of processing
- **Persistent memory** -- CLAUDE.md files at global and per-chat scopes, loaded into every request
- **Message splitting** -- long responses are automatically split at newline boundaries to fit channel limits (Telegram/WhatsApp)

## Tools

| Tool | Description |
|------|-------------|
| `bash` | Execute shell commands with configurable timeout |
| `read_file` | Read files with line numbers, optional offset/limit |
| `write_file` | Create or overwrite files (auto-creates directories) |
| `edit_file` | Find-and-replace editing with uniqueness validation |
| `glob` | Find files by pattern (`**/*.rs`, `src/**/*.ts`) |
| `grep` | Regex search across file contents |
| `read_memory` | Read persistent CLAUDE.md memory (global or per-chat) |
| `write_memory` | Write persistent CLAUDE.md memory |
| `web_search` | Search the web via DuckDuckGo (returns titles, URLs, snippets) |
| `web_fetch` | Fetch a URL and return plain text (HTML stripped, max 20KB) |
| `send_message` | Send mid-conversation messages; supports attachments for Telegram/WhatsApp/Discord via `attachment_path` + optional `caption` |
| `schedule_task` | Schedule a recurring (cron) or one-time task |
| `list_scheduled_tasks` | List all active/paused tasks for a chat |
| `pause_scheduled_task` | Pause a scheduled task |
| `resume_scheduled_task` | Resume a paused task |
| `cancel_scheduled_task` | Cancel a task permanently |
| `get_task_history` | View execution history for a scheduled task |
| `export_chat` | Export chat history to markdown |
| `sub_agent` | Delegate a sub-task to a parallel agent with restricted tools |
| `activate_skill` | Activate an agent skill to load specialized instructions |
| `todo_read` | Read the current task/plan list for a chat |
| `todo_write` | Create or update the task/plan list for a chat |

## Memory

MicroClaw maintains persistent memory via `CLAUDE.md` files, inspired by Claude Code's project memory:

```
microclaw.data/runtime/groups/
    CLAUDE.md                 # Global memory (shared across all chats)
    {chat_id}/
        CLAUDE.md             # Per-chat memory
```

Memory is loaded into the system prompt on every request. The model can read and update memory through tools -- tell it to "remember that I prefer Python" and it will persist across sessions.

## Skills

MicroClaw supports the [Anthropic Agent Skills](https://github.com/anthropics/skills) standard. Skills are modular packages that give the bot specialized capabilities for specific tasks.

```
microclaw.data/skills/
    pdf/
        SKILL.md              # Required: name, description + instructions
    docx/
        SKILL.md
```

**How it works:**
1. Skill metadata (name + description) is always included in the system prompt (~100 tokens per skill)
2. When the model determines a skill is relevant, it calls `activate_skill` to load the full instructions
3. The model follows the skill instructions to complete the task

**Built-in skills:** pdf, docx, xlsx, pptx, skill-creator, apple-notes, apple-reminders, apple-calendar, weather

**New macOS skills (examples):**
- `apple-notes` -- manage Apple Notes via `memo`
- `apple-reminders` -- manage Apple Reminders via `remindctl`
- `apple-calendar` -- query/create Calendar events via `icalBuddy` + `osascript`
- `weather` -- quick weather lookup via `wttr.in`

**Adding a skill:** Create a subdirectory under `microclaw.data/skills/` with a `SKILL.md` file containing YAML frontmatter (`name` and `description`) and markdown instructions.

**Commands:**
- `/skills` -- list all available skills

## Plan & Execute

For complex, multi-step tasks, the bot can create a plan and track progress:

```
You: Set up a new Rust project with CI, tests, and documentation
Bot: [creates a todo plan, then executes each step, updating progress]

1. [x] Create project structure
2. [x] Add CI configuration
3. [~] Write unit tests
4. [ ] Add documentation
```

Todo lists are stored at `microclaw.data/runtime/groups/{chat_id}/TODO.json` and persist across sessions.

## Scheduling

The bot supports scheduled tasks via natural language:

- **Recurring:** "Remind me to check the logs every 30 minutes" -- creates a cron task
- **One-time:** "Remind me at 5pm to call Alice" -- creates a one-shot task

Under the hood, recurring tasks use 6-field cron expressions (sec min hour dom month dow). The scheduler polls every 60 seconds for due tasks, runs the agent loop with the task prompt, and sends results to the originating chat.

Manage tasks with natural language:
```
"List my scheduled tasks"
"Pause task #3"
"Resume task #3"
"Cancel task #3"
```

## Install

### One-line installer (recommended)

```sh
curl -fsSL https://microclaw.ai/install.sh | bash
```

This installer only does one thing:
- Download and install the matching prebuilt binary from the latest GitHub release
- It does not fallback to Homebrew/Cargo inside `install.sh` (use separate methods below)

### Homebrew (macOS)

```sh
brew tap everettjf/tap
brew install microclaw
```

### From source

```sh
git clone https://github.com/microclaw/microclaw.git
cd microclaw
cargo build --release
cp target/release/microclaw /usr/local/bin/
```

## Local Web UI (cross-channel history)

When `web_enabled: true`, MicroClaw serves a local Web UI (default `http://127.0.0.1:10961`).

- Session list includes chats from all channels stored in SQLite (`telegram`, `whatsapp`, `discord`, `web`)
- You can review and manage history (refresh / clear context / delete)
- Non-web channels are read-only in Web UI by default (send from source channel)
- If there are no sessions yet, Web UI auto-generates a new key like `session-YYYYMMDDHHmmss`
- The first message in that session automatically persists it in SQLite

## Release

Publish both installer mode (GitHub Release asset used by `install.sh`) and Homebrew mode with one command:

```sh
./deploy.sh
```

## Setup

> **New:** MicroClaw now includes an interactive Q&A config flow (`microclaw config`) and will auto-launch it on first `start` when required config is missing.

### 1. Create a Telegram bot

1. Open Telegram and search for [@BotFather](https://t.me/BotFather)
2. Send `/newbot`
3. Enter a display name for your bot (e.g. `My MicroClaw`)
4. Enter a username (must end in `bot`, e.g. `my_microclaw_bot`)
5. BotFather will reply with a token like `123456789:ABCdefGHIjklMNOpqrsTUVwxyz` -- save this

**Recommended BotFather settings** (optional but useful):
- `/setdescription` -- set a short description shown in the bot's profile
- `/setcommands` -- register commands so users see them in the menu:
  ```
  reset - Clear current session
  skills - List available agent skills
  ```
- `/setprivacy` -- set to `Disable` if you want the bot to see all group messages (not just @mentions)

### 2. Get an LLM API key

Choose a provider and create an API key:
- Anthropic: [console.anthropic.com](https://console.anthropic.com/)
- OpenAI: [platform.openai.com](https://platform.openai.com/)
- Or any OpenAI-compatible provider (OpenRouter, DeepSeek, etc.)

### 3. Configure (recommended: interactive Q&A)

```sh
microclaw config
```

<!-- Setup wizard screenshot placeholder -->
<!-- Replace with real screenshot later -->
![Setup Wizard (placeholder)](screenshots/setup-wizard.png)

The `config` flow provides:
- Question-by-question prompts with defaults (`Enter` to confirm quickly)
- Provider selection + model selection (numbered choices with custom override)
- Better Ollama UX: local model auto-detection + sensible local defaults
- Safe `microclaw.config.yaml` save with automatic backup
- Auto-created directories for `data_dir` and `working_dir`

If you prefer the full-screen TUI, you can still run:

```sh
microclaw setup
```

Provider presets available in the wizard:
- `openai`
- `openrouter`
- `anthropic`
- `ollama`
- `google`
- `alibaba`
- `deepseek`
- `moonshot`
- `mistral`
- `azure`
- `bedrock`
- `zhipu`
- `minimax`
- `cohere`
- `tencent`
- `xai`
- `huggingface`
- `together`
- `custom` (manual provider/model/base URL)

For Ollama, `llm_base_url` defaults to `http://127.0.0.1:11434/v1`, `api_key` is optional, and the interactive config flow can auto-detect locally installed models.

You can still configure manually with `microclaw.config.yaml`:

```
telegram_bot_token: "123456:ABC-DEF1234..."
bot_username: "my_bot"
llm_provider: "anthropic"
api_key: "sk-ant-..."
model: "claude-sonnet-4-20250514"
# optional
# llm_base_url: "https://..."
data_dir: "./microclaw.data"
working_dir: "./tmp"
working_dir_isolation: "chat" # optional; defaults to "chat" if omitted
max_document_size_mb: 100
timezone: "UTC"
```

### 4. Run

```sh
microclaw start
```

### 5. Run as persistent gateway service (optional)

```sh
microclaw gateway install
microclaw gateway status
```

Manage service lifecycle:

```sh
microclaw gateway start
microclaw gateway stop
microclaw gateway logs 200
microclaw gateway uninstall
```

Notes:
- macOS uses `launchd` user agents.
- Linux uses `systemd --user`.
- Runtime logs are written to `microclaw.data/runtime/logs/`.
- Log file format is hourly: `microclaw-YYYY-MM-DD-HH.log`.
- Logs older than 30 days are deleted automatically.

## Configuration

All configuration is via `microclaw.config.yaml`:

| Key | Required | Default | Description |
|----------|----------|---------|-------------|
| `telegram_bot_token` | Yes | -- | Telegram bot token from BotFather |
| `api_key` | Yes* | -- | LLM API key (`ollama` can leave this empty) |
| `bot_username` | Yes | -- | Bot username (without @) |
| `llm_provider` | No | `anthropic` | Provider preset ID (or custom ID). `anthropic` uses native Anthropic API, others use OpenAI-compatible API |
| `model` | No | provider-specific | Model name |
| `llm_base_url` | No | provider preset default | Custom provider base URL |
| `data_dir` | No | `./microclaw.data` | Data root (`runtime` data in `data_dir/runtime`, skills in `data_dir/skills`) |
| `working_dir` | No | `./tmp` | Default working directory for tool operations; relative paths in `bash/read_file/write_file/edit_file/glob/grep` resolve from here |
| `working_dir_isolation` | No | `chat` | Working directory isolation mode for `bash/read_file/write_file/edit_file/glob/grep`: `shared` uses `working_dir/shared`, `chat` isolates each chat under `working_dir/chat/<channel>/<chat_id>` |
| `max_tokens` | No | `8192` | Max tokens per model response |
| `max_tool_iterations` | No | `100` | Max tool-use loop iterations per message |
| `max_document_size_mb` | No | `100` | Maximum allowed size for inbound Telegram documents; larger files are rejected with a hint message |
| `max_history_messages` | No | `50` | Number of recent messages sent as context |
| `control_chat_ids` | No | `[]` | Chat IDs that can perform cross-chat actions (send_message/schedule/export/memory global/todo) |
| `max_session_messages` | No | `40` | Message count threshold that triggers context compaction |
| `compact_keep_recent` | No | `20` | Number of recent messages to keep verbatim during compaction |

### Supported `llm_provider` values

`openai`, `openrouter`, `anthropic`, `ollama`, `google`, `alibaba`, `deepseek`, `moonshot`, `mistral`, `azure`, `bedrock`, `zhipu`, `minimax`, `cohere`, `tencent`, `xai`, `huggingface`, `together`, `custom`.

## Group chats

In private chats, the bot responds to every message. In groups, it only responds when mentioned with `@bot_username`. All messages in groups are still stored for context.

**Catch-up behavior:** When mentioned in a group, the bot loads all messages since its last reply in that group (instead of just the last N messages). This means it catches up on everything it missed, making group interactions much more contextual.

## Multi-chat permission model

Tool calls are authorized against the current chat:

- Non-control chats can only operate on their own `chat_id`
- Control chats (`control_chat_ids`) can operate across chats
- `write_memory` with `scope: "global"` is restricted to control chats

Affected tools include `send_message`, scheduling tools, `export_chat`, `todo_*`, and chat-scoped memory operations.

## Usage examples

**Web search:**
```
You: Search the web for the latest Rust release notes
Bot: [searches DuckDuckGo, returns top results with links]
```

**Web fetch:**
```
You: Fetch https://example.com and summarize it
Bot: [fetches page, strips HTML, summarizes content]
```

**Scheduling:**
```
You: Every morning at 9am, check the weather in Tokyo and send me a summary
Bot: Task #1 scheduled. Next run: 2025-06-15T09:00:00+00:00

[Next morning at 9am, bot automatically sends weather summary]
```

**Mid-conversation messaging:**
```
You: Analyze all log files in /var/log and give me a security report
Bot: [sends "Scanning log files..." as progress update]
Bot: [sends "Found 3 suspicious entries, analyzing..." as progress update]
Bot: [sends final security report]
```

**Coding help:**
```
You: Find all TODO comments in this project and fix them
Bot: [greps for TODOs, reads files, edits them, reports what was done]
```

**Memory:**
```
You: Remember that the production database is on port 5433
Bot: Saved to chat memory.

[Three days later]
You: What port is the prod database on?
Bot: Port 5433.
```

## Architecture

```
src/
    main.rs              # Entry point, CLI
    config.rs            # Environment variable loading
    error.rs             # Error types (thiserror)
    telegram.rs          # Telegram handler, agentic tool-use loop, session resume, context compaction, typing indicator
    whatsapp.rs          # Optional WhatsApp Cloud API webhook handler
    llm.rs               # LLM provider abstraction (Anthropic + OpenAI-compatible)
    claude.rs            # Canonical message/tool schema + Anthropic-compatible types
    db.rs                # SQLite: messages, chats, scheduled_tasks, sessions
    memory.rs            # CLAUDE.md memory system
    skills.rs            # Agent skills system (discovery, activation)
    scheduler.rs         # Background task scheduler (60s polling loop)
    tools/
        mod.rs           # Tool trait + registry (22 tools)
        bash.rs          # Shell execution
        read_file.rs     # File reading
        write_file.rs    # File writing
        edit_file.rs     # Find/replace editing
        glob.rs          # File pattern matching
        grep.rs          # Regex content search
        memory.rs        # Memory read/write tools
        web_search.rs    # DuckDuckGo web search
        web_fetch.rs     # URL fetching with HTML stripping
        send_message.rs  # Mid-conversation messaging (text + channel attachments)
        schedule.rs      # 5 scheduling tools (create/list/pause/resume/cancel)
        sub_agent.rs     # Sub-agent with restricted tool registry
        activate_skill.rs # Skill activation tool
        todo.rs          # Plan & execute todo tools
```

Key design decisions:
- **Session resume** persists full message history (including tool blocks) in SQLite; context compaction summarizes old messages to stay within limits
- **Provider abstraction** with native Anthropic + OpenAI-compatible endpoints
- **SQLite with WAL mode** for concurrent read/write from async context
- **Exponential backoff** on 429 rate limits (3 retries)
- **Message splitting** for long channel responses
- **`Arc<Database>`** shared across tools and scheduler for thread-safe DB access
- **Continuous typing indicator** via a spawned task that sends typing action every 4 seconds

## Documentation

| File | Description |
|------|-------------|
| [README.md](README.md) | This file -- overview, setup, usage |
| [DEVELOP.md](DEVELOP.md) | Developer guide -- architecture, adding tools, debugging |
| [TEST.md](TEST.md) | Manual testing guide for all features |
| [CLAUDE.md](CLAUDE.md) | Project context for AI coding assistants |
| [AGENTS.md](AGENTS.md) | Agent-friendly project reference |

## License

MIT

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=microclaw/microclaw&type=Date)](https://star-history.com/#microclaw/microclaw&Date)
