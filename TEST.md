# MicroClaw Testing Guide

This document describes how to test every feature of MicroClaw. It includes both automated tests (unit/integration) and manual black-box functional tests organized by user stories.

## Automated Tests

```sh
cargo test              # Run all unit + integration tests
cargo clippy            # Lint check
cargo fmt --check       # Format check
scripts/ci/stability_smoke.sh
```

Additional CI-equivalent quality checks:

```sh
npm --prefix web run build
npm --prefix website run build
node scripts/generate_docs_artifacts.mjs --check
cargo audit
cargo deny check advisories bans licenses
```

## Black-Box Functional Tests

Since MicroClaw is a multi-platform bot with external dependencies (LLM APIs, Telegram/Discord/WhatsApp APIs, DuckDuckGo), many features require live interaction testing.

### Prerequisites

1. A working `microclaw.config.yaml` file with valid credentials
2. `cargo build` succeeds with zero errors
3. Bot is running: `cargo run -- start`
4. A Telegram account to send messages
5. (For group tests) A Telegram group with the bot added as a member

---

## 1. Startup & Configuration

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 1.1 | First launch without config | Run `microclaw start` with no config.yaml present | Auto-launches setup wizard |
| 1.2 | Normal startup | Fill config.yaml, run `microclaw start` | Logs: Database initialized / Memory manager initialized / Scheduler started |
| 1.3 | Missing required field | Remove `api_key` from config, start | Error message + launches setup wizard |
| 1.4 | Invalid timezone | Set `timezone: "Mars/Olympus"` | Startup error with invalid timezone message |
| 1.5 | CLI help | `microclaw help` | Full output: commands, features, config docs |
| 1.6 | CLI version | `microclaw version` | Output: `microclaw {VERSION}` |
| 1.7 | Unknown command | `microclaw foobar` | "Unknown command: foobar" + help text |
| 1.8 | Setup wizard | `microclaw setup` | TUI interactive guide, provider/model selection |
| 1.9 | MICROCLAW_CONFIG env var | `MICROCLAW_CONFIG=/tmp/test.yaml microclaw start` | Loads config from specified path |

---

## 2. Private Chat -- Basic Conversation

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 2.1 | Send plain text | Private chat: send "Hello" | Bot responds; typing indicator visible during processing |
| 2.2 | Empty message | Send message with no text/image/voice | Bot does not respond, no crash |
| 2.3 | Very long input | Send 10000-character text | Bot processes and responds normally |
| 2.4 | Special characters | Send `<script>alert('xss')</script>` | XML-escaped, processed safely, no injection |
| 2.5 | Emoji/Unicode | Send various emoji and CJK characters | Processed and responded to normally |
| 2.6 | Long response splitting | Ask for a 5000-character essay | Response split at newline boundaries into multiple messages (max 4096 chars each) |
| 2.7 | Typing indicator persistence | Send request requiring multiple tool calls | Typing refreshes every ~4s until response completes |
| 2.8 | Rapid consecutive messages | Send 5 messages quickly | All stored; bot processes each without dropping any |

---

## 3. Image Handling

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 3.1 | JPEG photo | Send a JPEG photo | Bot describes image content |
| 3.2 | PNG screenshot | Send a PNG image | Correctly identified as PNG, processed |
| 3.3 | WebP image | Send a WebP format image | Correctly identified as WebP, processed |
| 3.4 | GIF image | Send an animated GIF | Correctly identified as GIF, processed |
| 3.5 | Image + caption | Send photo with caption "What is this?" | Bot sees both image and caption, responds accordingly |
| 3.6 | Image without caption | Send photo with no caption | Bot proactively describes image content |
| 3.7 | Image session persistence | Send image, then ask "What was in that image?" | Bot recalls image from session (stored as `[image was sent]` placeholder) |
| 3.8 | Large image | Send high-resolution image (5MB+) | Downloads largest resolution, processes without timeout |

---

## 4. Voice Messages

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 4.1 | Voice transcription (with key) | Send voice message (openai_api_key configured) | Bot transcribes via Whisper, processes as text |
| 4.2 | Voice without key | Send voice message (no openai_api_key) | "Voice messages not supported (no Whisper API key configured)" |
| 4.3 | Transcription failure | Send corrupted audio file | Embeds `[transcription failed: {error}]`, no crash |
| 4.4 | Long voice message | Send 2-minute voice message | Transcribed and processed normally |

---

## 5. Session Management

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 5.1 | Conversation continuity | Msg 1: "My name is Alice"; Msg 2: "What's my name?" | Bot remembers "Alice" |
| 5.2 | Tool context preserved | Msg 1: "Create /tmp/test.txt with hello"; Msg 2: "What did you just create?" | Bot remembers file operation (session includes tool_use/tool_result blocks) |
| 5.3 | /reset clears session | Chat several turns, send `/reset`, ask "What did we talk about?" | Bot does not remember previous session context |
| 5.4 | /archive session | Chat several turns, send `/archive` | Session archived to `<data_dir>/groups/<channel>/<chat_id>/conversations/<timestamp>.md` |
| 5.5 | Context compaction trigger | Chat beyond max_session_messages threshold | Old messages auto-summarized; recent messages kept verbatim |
| 5.6 | Memory after compaction | After compaction, ask about an early topic | Bot recalls key facts from summary (details may be lost) |
| 5.7 | Corrupted session recovery | Manually corrupt sessions table JSON, then send message | Falls back to DB history, no crash |
| 5.8 | Session survives restart | Chat several turns → restart bot → continue chatting | Session loaded from DB, conversation continues seamlessly |

---

## 6. Group Chat

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 6.1 | No @mention = no reply | Send plain message in group | Bot does not reply; message is stored in DB |
| 6.2 | @mention triggers reply | Send `@botusername hello` | Bot responds |
| 6.3 | Group catch-up | Multiple users send messages, then @bot "summarize" | Bot's response covers ALL messages since its last reply |
| 6.4 | allowed_groups whitelist (allowed) | Configure allowed_groups with current group ID | @mention works normally |
| 6.5 | allowed_groups whitelist (blocked) | Configure allowed_groups WITHOUT current group ID | @mention gets no response; messages still stored |
| 6.6 | allowed_groups empty | Set allowed_groups to [] or omit | All groups can @mention and get replies |
| 6.7 | Multi-group isolation | Chat in Group A, then @mention in Group B | Group B has independent session/memory, unaffected by Group A |

---

## 7. Tool -- Bash Execution

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 7.1 | Simple command | "Run `echo hello world`" | Returns "hello world" |
| 7.2 | Non-zero exit code | "Run `exit 1`" | Reports exit code 1 |
| 7.3 | stderr output | "Run `ls /nonexistent 2>&1`" | Returns stderr content |
| 7.4 | Command timeout | "Run `sleep 300`" | Times out after 120s |
| 7.5 | Output truncation | Command producing >30KB output | Output truncated with marker |
| 7.6 | Multi-step command | "Count the .rs files in this directory" | Bot uses bash correctly, returns result |

---

## 8. Tool -- File Operations

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 8.1 | Create file | "Create /tmp/test.txt with content hello" | File created successfully |
| 8.2 | Read file | "Read /tmp/test.txt" | Returns file content with line numbers |
| 8.3 | Edit file | "Change hello to world in /tmp/test.txt" | Find-replace succeeds |
| 8.4 | Read nonexistent file | "Read /nonexistent/file.txt" | Error: file not found, no crash |
| 8.5 | Edit non-unique string | File has multiple "hello", request replace | Error: string not unique |
| 8.6 | Read with offset/limit | "Read /tmp/big.txt from line 100, 20 lines" | Returns specified range |
| 8.7 | Auto-create directories | "Create /tmp/a/b/c/test.txt" | Intermediate directories auto-created, file written |
| 8.8 | Path guard: .ssh | "Read ~/.ssh/id_rsa" | Blocked by path_guard |
| 8.9 | Path guard: .env | "Read .env" | Blocked by path_guard |
| 8.10 | Path guard: .aws | "Read ~/.aws/credentials" | Blocked by path_guard |
| 8.11 | Path guard: /etc/shadow | "Read /etc/shadow" | Blocked by path_guard |

---

## 9. Tool -- File Search

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 9.1 | Glob search | "Find all .rs files in the project" | Returns matching file list |
| 9.2 | Glob no match | "Find *.xyz files" | Returns empty result or "no matches" |
| 9.3 | Grep content search | "Search for 'fn main' in source code" | Returns file names, line numbers, matching content |
| 9.4 | Grep regex search | "Search for `async fn.*execute`" | Regex matching works correctly |
| 9.5 | Grep no match | "Search for 'xyznotexist123'" | Returns no matches |
| 9.6 | Search excludes sensitive paths | Glob/Grep results | path_guard filters sensitive paths from results |

---

## 10. Tool -- Web Search & Fetch

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 10.1 | Web search | "Search for Rust programming language" | Returns DuckDuckGo results (title + URL + snippet) |
| 10.2 | Web search no results | Search for extremely obscure keywords | Returns empty or "no results" |
| 10.3 | Web fetch | "Fetch https://example.com" | Returns plain text with HTML tags stripped |
| 10.4 | Web fetch large page | Fetch page >20KB | Content truncated to 20KB |
| 10.5 | Web fetch invalid URL | "Fetch https://thisdomaindoesnotexist12345.com" | Returns network error, no crash |
| 10.6 | Combined web research | "Look up today's news and summarize" | Bot combines web_search + web_fetch to complete task |

---

## 11. Tool -- Mid-Conversation Messaging

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 11.1 | Progress update | "Send 'Processing...' first, then tell me today's date" | Receive TWO messages: progress + final reply |
| 11.2 | Only send_message | "Use send_message to say 'test' and nothing else" | Receive exactly ONE message "test", no empty reply |
| 11.3 | Cross-chat send (regular user) | "Send a message to chat_id 99999" | Permission denied |
| 11.4 | Cross-chat send (control chat) | From control_chat_id, specify another chat_id | Message sent successfully |

---

## 12. Memory System

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 12.1 | Write chat memory | "Remember I like Rust" | Written to `<data_dir>/groups/{chat_id}/AGENTS.md` |
| 12.2 | Read chat memory | "What language do I like?" | Bot recalls "Rust" from memory |
| 12.3 | Memory persists across /reset | `/reset`, then "What do I like?" | Still recalls (memory is independent of session) |
| 12.4 | Memory persists across restart | Restart bot, then ask | Still recalls (memory is file-persisted) |
| 12.5 | Write global memory (control) | From control chat, write global memory | Written to `<data_dir>/groups/AGENTS.md` |
| 12.6 | Write global memory (regular) | From regular chat, attempt global write | "Permission denied: chat {id} cannot write global memory" |
| 12.7 | Read empty memory | New chat, first read | "No memory file found (not yet created)." |
| 12.8 | Memory overwrite | Write twice with different content | Second write completely replaces first |
| 12.9 | Cross-chat read memory (regular) | Read another chat_id's memory | Permission denied |
| 12.10 | Cross-chat read memory (control) | From control chat, read other chat memory | Returns content normally |

---

## 13. Scheduled Tasks

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 13.1 | Create cron task | "Remind me to drink water every 5 minutes" | Returns Task #{id} scheduled, cron: `0 */5 * * * *` |
| 13.2 | Create one-time task | "Send 'Happy New Year' at 2099-12-31T23:59:00+00:00" | Returns Task #{id} scheduled (once) |
| 13.3 | Task actually fires | Create per-minute task, wait 60-90s | Automatically receive task execution result |
| 13.4 | List tasks | "List my scheduled tasks" | Shows all active/paused tasks with details |
| 13.5 | Pause task | "Pause task #1" | Confirmed paused; task stops firing |
| 13.6 | Resume task | "Resume task #1" | Confirmed resumed; task resumes firing |
| 13.7 | Cancel task | "Cancel task #1" | Confirmed cancelled; permanently stopped |
| 13.8 | View execution history | "Show task #1 execution history" | Shows recent runs (time, duration, success/fail, summary) |
| 13.9 | Nonexistent task | "Pause task #9999" | "Task #9999 not found" |
| 13.10 | Invalid cron expression | Pass "not a cron" | Invalid cron expression error |
| 13.11 | Invalid timezone | Create task with timezone "invalid" | Invalid timezone error |
| 13.12 | Cross-chat schedule (regular) | Regular chat schedules for other chat_id | Permission denied |
| 13.13 | Cross-chat schedule (control) | Control chat schedules for other chat_id | Created successfully |
| 13.14 | Empty task list | New chat lists tasks | "No scheduled tasks found for this chat." |
| 13.15 | One-time task completion | Create imminent one-time task | After firing, status becomes "completed" |

---

## 14. Todo System

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 14.1 | Read empty todo | New chat, read todos | "No tasks in the todo list." |
| 14.2 | Create todo list | "Create 3 todo items for me" | Bot uses todo_write, returns formatted list |
| 14.3 | Update todo status | "Mark the first item as completed" | Bot reads existing → modifies status → writes back |
| 14.4 | Todo full replacement | Write, then write completely different list | Old list fully replaced |
| 14.5 | Cross-chat read todo (regular) | Read another chat_id's todos | Permission denied |
| 14.6 | Cross-chat read todo (control) | Control chat reads other chat_id's todos | Returns normally |
| 14.7 | Todo status icons | Create list with pending/in_progress/completed | Shows `[ ]`, `[~]`, `[x]` respectively |

---

## 15. Chat Export

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 15.1 | Export current chat | "Export this chat's history" | Generates markdown file, returns path and message count |
| 15.2 | Export to specific path | Specify path parameter | File written to specified path |
| 15.3 | Export empty chat | Export chat_id with no messages | "No messages found for chat {id}." |
| 15.4 | Export format verification | Export, then read the file | Each message: `**{sender}** ({timestamp})\n\n{content}\n\n---` |
| 15.5 | Cross-chat export (regular) | Export another chat_id | Permission denied |
| 15.6 | Cross-chat export (control) | Control chat exports other chat_id | Exported successfully |

---

## 16. Session-Native Subagents

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 16.1 | Spawn subagent run | Ask the bot to delegate repo inspection work | Bot creates a `sessions_spawn` run and returns a durable run ID |
| 16.2 | Inspect active runs | Ask to list or inspect the latest run | `subagents_list` / `subagents_info` show status, budget, and result fields |
| 16.3 | Continue focused run | Focus a run, then send follow-up work | `subagents_send` continues the same run instead of creating a fresh one |
| 16.4 | Cancel stale run | Cancel an active run | `subagents_kill` marks the run cancelled and the run stops progressing |
| 16.5 | Orchestrated fan-out | Ask for a bounded multi-worker delegation task | `subagents_orchestrate` creates multiple child runs within configured limits |
| 16.6 | Budget handling | Run a large task with too-small token budget | Run ends with `budget_exceeded` and reports input/output totals |
| 16.7 | Configured budget increase | Raise `subagents.max_tokens_per_run`, rerun the task | The same task completes successfully or gets materially farther |

---

## 16A. ACP Stdio Mode

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 16A.1 | ACP startup | Run `microclaw acp` | MicroClaw starts as an ACP stdio server |
| 16A.2 | ACP session continuity | Use one ACP client session for two turns | Second turn keeps prior context |
| 16A.3 | ACP cancellation | Start a long-running ACP request, then send `/stop` | Active ACP run is cancelled cleanly |

---

## 17. Browser Automation

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 17.1 | Open webpage | "Open https://example.com in browser" | Returns page content/status |
| 17.2 | Get page text | After opening, "get the page title" | Returns "Example Domain" |
| 17.3 | Screenshot | "Take a screenshot of the current page" | Screenshot saved successfully |
| 17.4 | Timeout handling | Open a very slow page | Returns timeout message after 30s |
| 17.5 | Browser session persistence | Log into a site, then restart conversation | Browser profile retains cookies/localStorage |
| 17.6 | Output truncation | Get content of a very large page | Output truncated to 30000 characters |

---

## 18. Skills System

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 18.1 | /skills list | Send `/skills` | Lists all available skills (name + description) |
| 18.2 | /skills when empty | Delete skills directory, send `/skills` | "No skills available." |
| 18.3 | Activate skill | Ask bot to use a specific skill | Bot uses activate_skill to load full instructions |
| 18.4 | Skill auto-discovery | Add new skill directory + SKILL.md under `<data_dir>/skills/` | After restart, `/skills` shows new skill |

---

## 19. MCP Integration

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 19.1 | MCP tools loaded | Configure mcp.json, start bot | Log: "MCP initialized: N tools available" |
| 19.2 | MCP tool usage | Ask bot to use an MCP-provided tool | MCP server called, result returned |
| 19.3 | No MCP config | Start without mcp.json | Normal startup, no MCP logs |

---

## 20. Multi-Step Tool Use (Agentic Loop)

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 20.1 | Multi-step task | "Find all TODO comments and write to /tmp/todos.txt" | Bot uses grep → read_file → write_file across multiple iterations |
| 20.2 | Error recovery | Request reading nonexistent file; bot should adapt | Bot receives tool error, adjusts strategy |
| 20.3 | Iteration limit reached | Send request requiring >max_tool_iterations | "I reached the maximum number of tool iterations..." |
| 20.4 | Tool composition | "Find the longest function and summarize it" | Bot combines grep → read_file → analysis |

---

## 21. Permission Model Matrix

| # | Operation | Regular→Self | Regular→Other | Control→Other |
|---|----------|-------------|--------------|--------------|
| 21.1 | send_message | Allow | Deny | Allow |
| 21.2 | schedule_task | Allow | Deny | Allow |
| 21.3 | pause/resume/cancel_task | Allow (own) | Deny | Allow |
| 21.4 | list_tasks | Allow (own) | Deny | Allow |
| 21.5 | get_task_history | Allow (own) | Deny | Allow |
| 21.6 | write_memory (chat) | Allow | Deny | Allow |
| 21.7 | write_memory (global) | Deny | N/A | Allow |
| 21.8 | read_memory (chat) | Allow | Deny | Allow |
| 21.9 | export_chat | Allow | Deny | Allow |
| 21.10 | todo_read/write | Allow | Deny | Allow |

---

## 22. Security -- Path Guard

| # | Test Path | Expected |
|---|----------|----------|
| 22.1 | `~/.ssh/id_rsa` | Blocked |
| 22.2 | `~/.ssh/known_hosts` | Blocked |
| 22.3 | `~/.aws/credentials` | Blocked |
| 22.4 | `~/.gnupg/*` | Blocked |
| 22.5 | `.env` | Blocked |
| 22.6 | `.env.local` / `.env.production` | Blocked |
| 22.7 | `~/.kube/config` | Blocked |
| 22.8 | `~/.config/gcloud/*` | Blocked |
| 22.9 | `/etc/shadow` | Blocked |
| 22.10 | `/etc/sudoers` | Blocked |
| 22.11 | `~/.netrc` | Blocked |
| 22.12 | `~/.npmrc` | Blocked |
| 22.13 | Path traversal `../../.ssh/id_rsa` | Still blocked |
| 22.14 | Normal path `/tmp/test.txt` | Allowed |

---

## 23. Discord Platform

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 23.1 | DM direct reply | Send DM to bot on Discord | Bot responds directly |
| 23.2 | Server requires @mention | Send message without @mention in server channel | No reply; message stored |
| 23.3 | Server @mention | @Bot in server channel | Bot responds |
| 23.4 | Response splitting | Trigger response >2000 chars | Split at newline boundaries, max 2000 chars per message |
| 23.5 | /reset command | Send `/reset` | Discord chat session cleared |
| 23.6 | /skills command | Send `/skills` | Lists available skills |
| 23.7 | /archive command | Send `/archive` | Archives current session |
| 23.8 | allowed_channels whitelist | Configure discord_allowed_channels | Only responds in allowed channels |
| 23.9 | Ignore other bots | Another bot sends a message | Bot does not respond |

---

## 24. WhatsApp Platform

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 24.1 | Webhook verification (valid) | GET `/webhook` with correct verify_token | Returns challenge |
| 24.2 | Webhook verification (invalid) | GET `/webhook` with wrong verify_token | Rejected |
| 24.3 | Text message processing | Send text via WhatsApp | Bot responds |
| 24.4 | Non-text message | Send image/audio | Silently skipped, no crash |
| 24.5 | /reset command | Send `/reset` | Session cleared |
| 24.6 | Response splitting | Trigger long response | Split at 4096-char boundaries |
| 24.7 | Send failure | WhatsApp API unreachable | Error logged; HTTP 200 still returned |

---

## 25. Gateway Service Management

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 25.1 | Install service | `microclaw gateway install` | macOS: LaunchAgent; Linux: systemd service |
| 25.2 | Start service | `microclaw gateway start` | Service starts |
| 25.3 | Check status | `microclaw gateway status` | Reports running state |
| 25.4 | View logs | `microclaw gateway logs 50` | Shows last 50 log lines |
| 25.5 | Stop service | `microclaw gateway stop` | Service stops |
| 25.6 | Uninstall service | `microclaw gateway uninstall` | Service removed |

---

## 26. Error Handling & Recovery

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| 26.1 | API rate limiting | Trigger Anthropic 429 response | Exponential backoff retry, up to 3 attempts |
| 26.2 | API unavailable | API completely unreachable | Returns "Error: {message}", no crash |
| 26.3 | DB corruption recovery | Delete DB file, then send message | Recreates DB or reports error, no crash |
| 26.4 | Tool execution exception | Tool internal panic/error | ToolResult::error returned to Claude, agentic loop continues |
| 26.5 | No messages to process | Empty history | "I didn't receive any message to process." |
| 26.6 | Role merge: consecutive user | DB history has user+user messages | Auto-merged into one user message |
| 26.7 | Role fix: trailing assistant | History ends with assistant message | Trailing assistant message auto-removed |

---

## Platform Adapter Template (Future Channels)

Use this checklist when adding a new platform adapter (for example Slack/Feishu/Teams).

### Adapter metadata

- Platform name: `<platform>`
- Inbound mode: `<webhook|gateway|polling>`
- Identity key mapping: `<platform chat/channel/user IDs -> stable chat_id>`
- Reply trigger policy: `<dm always / group mention / allowlist>`
- Message length limit: `<N chars>`
- Attachment support: `<yes/no + types>`

### Test matrix

| # | User Story | Steps | Expected |
|---|-----------|-------|----------|
| P.1 | Private/DM reply | Send direct message | Bot responds |
| P.2 | Group/channel no trigger | Send group message without trigger | No reply; message persistence matches policy |
| P.3 | Group/channel trigger | Mention or trigger bot in group/channel | Bot responds |
| P.4 | Long response splitting | Ask for response > platform limit | Split correctly at boundary with no truncation |
| P.5 | Session reset | Send `/reset` equivalent | Session cleared for this platform chat |
| P.6 | Session resume | Multi-turn chat -> restart bot -> continue | Session restored from DB |
| P.7 | Attachment ingress | Send supported attachment | Parsed/handled with expected behavior |
| P.8 | Attachment egress | Trigger `send_message` with attachment | Delivery succeeds or clear error reported |
| P.9 | Channel allowlist | Configure adapter channel allowlist | Replies limited to configured channels |
| P.10 | Ignore bot/system messages | Send from another bot/system user | Bot does not self-trigger or loop |
| P.11 | API failure handling | Simulate platform API/network failure | Error logged; process stays healthy |
| P.12 | Rate limit handling | Trigger adapter/platform rate limit | Backoff/retry policy works, no crash |

### Persistence and schema checks

- `messages` rows are written with correct `chat_id`, `sender_name`, `is_from_bot`, and timestamp.
- `sessions` row key remains stable for the same platform conversation across restarts.
- `chats.chat_type` semantics are consistent with trigger policy.
- Scheduled task replies route correctly back to the originating platform chat.

### Security and authorization checks

- `control_chat_ids` policy is enforced for cross-chat tools.
- Tool safety boundaries (path guard, restricted tools) remain unchanged by adapter.
- Mention parsing cannot be spoofed by plain text edge cases.

---

## Database Verification

After running tests, verify the database directly:

```sh
sqlite3 microclaw.data/runtime/microclaw.db

-- Check messages are stored
SELECT COUNT(*) FROM messages;

-- Check scheduled tasks
SELECT * FROM scheduled_tasks;

-- Check chat records
SELECT * FROM chats;

-- Check sessions
SELECT chat_id, length(messages_json), updated_at FROM sessions;

-- Check task run logs
SELECT * FROM task_run_logs ORDER BY started_at DESC LIMIT 10;
```

---

## Cleanup

After testing:

```sh
# Remove test files
rm -f /tmp/microclaw_test.txt /tmp/todos.txt /tmp/test.txt /tmp/session_test.txt

# Cancel any remaining scheduled tasks via the bot, or:
sqlite3 microclaw.data/runtime/microclaw.db "UPDATE scheduled_tasks SET status='cancelled' WHERE status='active';"
```
