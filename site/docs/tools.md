---
id: tools
title: Tools Reference
sidebar_position: 6
---

MicroClaw exposes built-in tools to LLM through JSON Schema definitions (plus optional MCP-federated tools). LLM selects and calls tools automatically based on your request.

For anti-drift, this page is complemented by the generated source-of-truth at [Generated Tools](./generated-tools), produced from code by `scripts/generate_docs_artifacts.mjs` (currently **58 built-in tools**). The curated table below highlights the most-used tools; the generated page is authoritative for the full set.

Skill workflows are provided by local `SKILL.md` files — MicroClaw ships **42 factory-ready built-in skills** (see [Skills](./skills)) and loads them through `activate_skill`.

## Tool List (Curated)

| # | Tool | Category | Description |
|---|---|---|---|
| 1 | `bash` | Shell | Execute shell commands with configurable timeout |
| 2 | `browser` | Web | Headless browser automation via agent-browser CLI |
| 3 | `read_file` | File I/O | Read files with line numbers, optional offset/limit |
| 4 | `write_file` | File I/O | Create or overwrite files (auto-creates directories) |
| 5 | `edit_file` | File I/O | Find-and-replace with uniqueness validation |
| 6 | `glob` | Search | Find files by glob pattern (`**/*.rs`) |
| 7 | `grep` | Search | Regex search across file contents |
| 8 | `read_memory` | Memory | Read persistent AGENTS.md memory |
| 9 | `write_memory` | Memory | Write persistent AGENTS.md memory |
| 10 | `web_search` | Web | Search via DuckDuckGo (top 8 results) |
| 11 | `web_fetch` | Web | Fetch a URL and return plain text (max 20KB) |
| 12 | `send_message` | chat | Send text mid-conversation; supports file attachments for Telegram/Discord/Slack/Weixin |
| -- | `session_search` | Search | Cross-conversation full-text recall (SQLite FTS5) |
| -- | `generate_image` | Media | Text-to-image via OpenAI-compatible `/images` |
| -- | `describe_image` | Media | Vision description via a vision-capable model |
| -- | `text_to_speech` | Media | TTS via OpenAI-compatible `/audio/speech` |
| -- | `transcribe_audio` | Media | STT via OpenAI-compatible `/audio/transcriptions` |
| -- | `fetch_artifact` | Runtime | Slice into an oversized tool result stashed by id |
| -- | `clarify` | chat | Ask a structured up-to-4-choice clarifying question |
| -- | `calculate` | Compute | Exact arithmetic without LLM mental math |
| -- | `osv_check` | Security | Query osv.dev for dependency advisories |
| -- | `insights` | Observability | Usage summary over a trailing window |
| -- | `knowledge_graph_query` / `knowledge_graph_add` | Memory | Query / add temporal knowledge-graph triples |
| 13 | `schedule_task` | Scheduler | Create a recurring or one-time task |
| 14 | `list_scheduled_tasks` | Scheduler | List active/paused tasks for a chat |
| 15 | `pause_scheduled_task` | Scheduler | Pause a scheduled task |
| 16 | `resume_scheduled_task` | Scheduler | Resume a paused task |
| 17 | `cancel_scheduled_task` | Scheduler | Cancel a scheduled task |
| 18 | `get_task_history` | Scheduler | View execution history for a task |
| 19 | `export_chat` | chat | Export chat history to markdown |
| 20 | `sessions_spawn` | Agent | Spawn an async sub-agent run; accepts a `specialist` profile and a human `label`, returns immediately |
| -- | `report_progress` | Agent | Sub-agent-only: emit a throttled `📊 [label] (n%)` mid-run progress update |
| -- | `consult_specialist` | Agent | Sub-agent-only: get an inline expert opinion from a different specialist (single round, no tools, no recursion) |
| -- | `subagents_orchestrate` | Agent | Fan out a templated set of worker sub-agents |
| 21 | `subagents_list` | Agent | List sub-agent runs for the current chat (with labels + latest progress) |
| 22 | `subagents_info` | Agent | Inspect one sub-agent run by run_id or label |
| 23 | `subagents_kill` | Agent | Cancel one run (by run_id or label) or all active runs in the chat |
| 24 | `subagents_focus` | Agent | Focus the chat on a specific sub-agent run |
| 25 | `subagents_unfocus` | Agent | Clear focused sub-agent binding |
| 26 | `subagents_focused` | Agent | Show current focused sub-agent run |
| 27 | `subagents_send` | Agent | Send follow-up work to focused run as continuation |
| 28 | `subagents_log` | Agent | Read timeline events for one sub-agent run |
| 29 | `subagents_retry_announces` | Agent | Retry pending completion announces (control chats) |
| 30 | `activate_skill` | Skills | Load specialized local skill instructions |
| 31 | `sync_skills` | Skills | Sync external skills into local `~/.microclaw/skills` with normalized metadata |
| 32 | `todo_read` | Planning | Read persistent todo list for a chat |
| 33 | `todo_write` | Planning | Write/replace persistent todo list for a chat |
| 34 | `structured_memory_search` | Memory | Search structured memories (keyword, optional archived include) |
| 35 | `structured_memory_delete` | Memory | Archive a structured memory by ID (soft delete) |
| 36 | `structured_memory_update` | Memory | Update structured memory content/category by ID |

---

## Detailed Parameters

## Permission model

Tool calls are authorized by caller chat:

- Non-control chats can only operate on their own `chat_id`
- Control chats (`control_chat_ids`) can operate across chats
- Global memory writes (`write_memory` with `scope = "global"`) require control-chat privileges

This applies to `send_message`, scheduler tools, `export_chat`, `todo_*`, and chat-scoped memory access.

### Specialist sub-agents

`sessions_spawn` can route a task to a **specialist profile** — a preset persona plus a tool subset — instead of a single generic worker. The main agent stays light in the foreground and dispatches the right expert in the background:

```json
{ "specialist": "mathematician", "label": "prove convergence", "task": "…" }
```

| Specialist | Focus | Extra tools |
|---|---|---|
| `mathematician` | step-by-step derivation, verify with code | code exec |
| `illustrator` | visual brief, prompt iteration | `generate_image`, `describe_image` |
| `researcher` | multi-source retrieval, cross-check, cite | `web_search`, `web_fetch` |
| `coder` | read/write code, run tests, minimal diffs | file tools, `bash` |
| `writer` | structured writing, tone/length control | memory/context |
| `analyst` | classify data, statistics, charts | code exec, file tools |
| `generalist` | default catch-all | restricted set |

Within a run, a sub-agent can call `report_progress` to post a throttled mid-run update, and `consult_specialist` to get an inline opinion from a *different* specialist (single LLM round, no tools, no recursion, no chat side effects). Concurrent runs carry human `label`s, so they can be inspected or cancelled by name. Adding a specialist is one record in the roster — no change to the core loop.

### bash

Execute a shell command.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `command` | string | Yes | The bash command to execute |
| `timeout_secs` | integer | No | Timeout in seconds (default: 120) |

**Behavior**: Returns stdout + stderr. Output truncated at 30,000 characters. Non-zero exit codes are reported as errors.

---

### browser

Headless browser automation via [agent-browser](https://github.com/vercel-labs/agent-browser) CLI. Requires `agent-browser` to be installed (see [Installation](/docs/installation#optional-browser-automation)).

| Parameter | Type | Required | Description |
|---|---|---|---|
| `command` | string | Yes | The agent-browser command to run |
| `timeout_secs` | integer | No | Timeout in seconds (default: 30) |

**Commands by category**:

| Category | Commands |
|---|---|
| Navigation | `open <url>`, `back`, `forward`, `reload`, `close` |
| Snapshot | `snapshot` (`-i` interactive only, `-c` compact) |
| Interaction | `click`, `dblclick`, `fill`, `type`, `press`, `hover`, `select`, `check`, `uncheck`, `upload`, `drag` |
| Data extraction | `get text/html/value/attr/title/url/count/box <sel>` |
| State checks | `is visible/enabled/checked <sel>` |
| Screenshot/PDF | `screenshot [path]` (`--full` for full page), `pdf <path>` |
| JavaScript | `eval <js>` |
| Cookies | `cookies`, `cookies set <name> <val>`, `cookies clear` |
| Storage | `storage local [key]`, `storage local set <k> <v>`, `storage local clear` (same for `session`) |
| Tabs | `tab`, `tab new [url]`, `tab <n>`, `tab close [n]` |
| Frames | `frame <sel>`, `frame main` |
| Dialogs | `dialog accept [text]`, `dialog dismiss` |
| Viewport | `set viewport <w> <h>`, `set device <name>`, `set media dark/light` |
| Network | `network route <url>` (`--abort`, `--body <json>`), `network requests` |
| Wait | `wait <sel\|ms\|--text\|--url\|--load\|--fn>` |
| Auth state | `state save <path>`, `state load <path>` |
| Semantic find | `find role/text/label/placeholder <value> <action> [input]` |
| Scrolling | `scroll <dir> [px]`, `scrollintoview <sel>` |

**State persistence**: Browser state persists at two levels:

- **Within a conversation** (`--session`): cookies, page state, and tabs stay alive across tool calls
- **Across conversations** (`--profile`): cookies, localStorage, IndexedDB, and login sessions are saved to disk per chat at `<data_dir>/groups/<chat_id>/browser-profile/`

Output truncated at 30,000 characters. Always run `snapshot -i` after navigation or interaction to see the updated page state.

---

### read_file

Read file content with line numbers.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `path` | string | Yes | File path to read |
| `offset` | integer | No | Line number to start from (1-based) |
| `limit` | integer | No | Maximum lines to read (default: 2000) |

**Output format**: `{line_number}\t{content}` per line.

---

### write_file

Create or overwrite a file.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `path` | string | Yes | File path to write |
| `content` | string | Yes | Content to write |

**Behavior**: Creates parent directories automatically if they don't exist.

---

### edit_file

Replace an exact string in a file.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `path` | string | Yes | File path to edit |
| `old_string` | string | Yes | Exact string to find (must be unique) |
| `new_string` | string | Yes | Replacement string |

**Validation**: Fails if `old_string` is not found or appears more than once.

---

### glob

Find files matching a glob pattern.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `pattern` | string | Yes | Glob pattern (e.g., `**/*.rs`, `src/*.ts`) |
| `path` | string | No | Base directory (default: current directory) |

**Behavior**: Results sorted alphabetically. Truncated at 500 matches.

---

### grep

Search file contents with regex.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `pattern` | string | Yes | Regex pattern to search for |
| `path` | string | No | File or directory (default: current directory) |
| `glob` | string | No | Glob filter for filenames (e.g., `*.rs`) |

**Behavior**: Recursively searches directories. Skips hidden directories (`.git`, `.hidden`), `node_modules`, and `target`. Results truncated at 500 matches. Max 10,000 files scanned.

---

### read_memory

Read persistent AGENTS.md memory file.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `scope` | string | Yes | `"global"`, `"bot"`, or `"chat"` |
| `chat_id` | integer | For chat scope | Chat ID for chat-scoped memory |

---

### write_memory

Write to AGENTS.md memory file.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `scope` | string | Yes | `"global"`, `"bot"`, or `"chat"` |
| `chat_id` | integer | For chat scope | Chat ID for chat-scoped memory |
| `content` | string | Yes | Content to write (`global`/`bot` replace full file; `chat` updates latest sender section when available) |

---

### structured_memory_search

Search structured memories persisted in SQLite.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `query` | string | Yes | Keyword query |
| `limit` | integer | No | Max results (default 10, max 50) |
| `include_archived` | boolean | No | Include archived memories (default false) |

---

### structured_memory_delete

Archive a structured memory by ID (soft delete).

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | integer | Yes | Memory row ID |

---

### structured_memory_update

Update structured memory content/category in place.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | integer | Yes | Memory row ID |
| `content` | string | Yes | New content |
| `category` | string | No | `PROFILE` / `KNOWLEDGE` / `EVENT` |

---

### web_search

Search the web via DuckDuckGo.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `query` | string | Yes | Search query |

**Returns**: Top 8 results with title, URL, and snippet.

---

### web_fetch

Fetch a URL and return plain text.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `url` | string | Yes | URL to fetch |

**Behavior**: Strips HTML tags, collapses whitespace, truncates at 20KB. Follows up to 5 redirects. 15-second timeout.

---

### send_message

Send a chat message mid-conversation.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `chat_id` | integer | Yes | Chat ID to send to |
| `text` | string | No | Message text |
| `attachment_path` | string | No | Local file path (channel attachment upload) |
| `caption` | string | No | Optional caption for attachment |

**Validation**: You must provide `text` and/or `attachment_path`.

**Notes**:
- `attachment_path` supports Telegram / Discord / Slack / Weixin targets
- Telegram sends as document attachment
- Discord sends as file attachment in channel message
- Web chat targets still append text to local Web conversation

---

### schedule_task

Create a scheduled task.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `chat_id` | integer | Yes | Chat ID for results |
| `prompt` | string | Yes | Prompt to execute at scheduled time |
| `schedule_type` | string | Yes | `"cron"` or `"once"` |
| `schedule_value` | string | Yes | 6-field cron expression or ISO 8601 timestamp |

---

### list_scheduled_tasks

List tasks for a chat.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `chat_id` | integer | Yes | Chat ID to list tasks for |

**Returns**: Active and paused tasks with ID, status, prompt, schedule, and next run time.

---

### pause_scheduled_task / resume_scheduled_task / cancel_scheduled_task

Manage a scheduled task by ID.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `task_id` | integer | Yes | Task ID to pause/resume/cancel |

---

## Adding a New Tool

1. Create `src/tools/my_tool.rs` implementing the `Tool` trait:
   - `name()` — tool name string
   - `definition()` — `ToolDefinition` with JSON Schema
   - `execute(input)` — async execution returning `ToolResult`
2. Add `pub mod my_tool;` to `src/tools/mod.rs`
3. Register in `ToolRegistry::new()` with `Box::new(my_tool::MyTool::new(...))`

Trait/runtime note: `Tool` and `ToolResult` live in `microclaw_tools::runtime`; `src/tools/mod.rs` reuses those shared primitives.

If your tool needs shared state (Bot, Database), add a constructor that accepts the dependency.
