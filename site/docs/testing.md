---
id: testing
title: Testing Guide
sidebar_position: 11
---

## Unit Tests

MicroClaw has 200+ unit tests covering core modules and permission paths. Run them with:

```sh
cargo test
```

Targeted checks for the recently merged features:

```sh
cargo test acp::tests
cargo test tools::subagents::tests
cargo test memory_service
cargo test web::tests::test_send_stream_then_stream_done
```

### Test coverage by module

| Module | Tests | What's covered |
|---|---|---|
| `db.rs` | 13 | Database creation, chat upsert, message CRUD, ordering, catch-up queries, scheduled task CRUD, status lifecycle |
| `memory.rs` | 8 | Path construction, read/write global and chat memory, build_memory_context with various states |
| `llm_types.rs` | 11 | Serialization/deserialization of shared API types and request/response round-trips |
| `config.rs` | 2 | Struct cloning, default values |
| `error.rs` | 4 | Display formatting, From trait conversions, Debug output |
| `telegram.rs` | 10 | Message merging, trailing/leading assistant removal, system prompt building, response splitting |
| `tools/mod.rs` | 4 | ToolResult constructors, schema_object helper |
| `tools/bash.rs` | 6 | Echo, exit codes, stderr, timeout, missing params, definition |
| `tools/read_file.rs` | 4 | Normal read, offset+limit, file not found, missing params |
| `tools/write_file.rs` | 3 | Normal write, auto-create dirs, missing params |
| `tools/edit_file.rs` | 5 | Successful edit, file not found, string not found, multiple matches, missing params |
| `tools/glob.rs` | 3 | File matching, no matches, missing params |
| `tools/grep.rs` | 7 | Content matching, no matches, file glob filter, invalid regex, hidden dir skipping |
| `tools/memory.rs` | 10+ | Global/chat read and write, missing params, invalid scope, empty files, permission deny/allow paths |
| `tools/schedule.rs` | 15+ | cron next_run computation, task creation (cron/once), validation, listing, pause/resume/cancel lifecycle, cross-chat authorization |

---

## Manual Testing Checklist

These tests require a running bot with valid credentials.

### Prerequisites

1. A working `microclaw.config.yaml` file with at least one channel configured under `channels.<name>.accounts`, matching bot username overrides when needed (`bot_username`, `channels.<name>.bot_username`, or `channels.<name>.accounts.<id>.bot_username`), and LLM auth (`api_key` for most providers, or OAuth via `codex login` for `openai-codex`)
2. Bot is running: `cargo run -- start`
3. A chat account with a private chat open to the bot
4. (For group tests) A chat group with the bot added as a member

### Test 1: Basic conversation

Send a simple message in private chat.

```
You: Hello, what can you do?
```

**Expected**: Bot responds with a description of its capabilities. Typing indicator should appear while processing.

---

### Test 2: Bash tool

```
You: Run `echo hello world` in bash
```

**Expected**: Bot returns "hello world".

```
You: Run `ls -la /tmp` and tell me the total file count
```

**Expected**: Bot executes ls, counts files, and reports.

---

### Test 3: File write + read

```
You: Create a file /tmp/microclaw_test.txt with the content "MicroClaw test file"
```

**Expected**: "Successfully wrote to /tmp/microclaw_test.txt"

```
You: Read the file /tmp/microclaw_test.txt
```

**Expected**: Displays file content with line numbers.

---

### Test 4: File edit

```
You: In /tmp/microclaw_test.txt, change "test file" to "works great"
```

**Expected**: "Successfully edited /tmp/microclaw_test.txt". Verify with:

```
You: Read /tmp/microclaw_test.txt
```

**Expected**: "MicroClaw works great"

---

### Test 5: Glob search

```
You: Find all .toml files in the current project directory
```

**Expected**: Lists `Cargo.toml` and any other .toml files.

---

### Test 6: Grep search

```
You: Search for "fn main" in all .rs files in the src directory
```

**Expected**: Returns matching lines with file paths and line numbers.

---

### Test 7: Web search

```
You: Search the web for "Rust programming language"
```

**Expected**: Returns numbered results with titles, URLs, and snippets from DuckDuckGo.

---

### Test 8: Web fetch

```
You: Fetch https://httpbin.org/get and show me the result
```

**Expected**: Returns the JSON response from httpbin.

---

### Test 9: Memory write + read

```
You: Remember that my favorite color is blue
```

**Expected**: Bot confirms it saved to memory.

```
You: What is my favorite color?
```

**Expected**: Bot answers "blue" (from memory).

---

### Test 10: Scheduling (cron)

```
You: Schedule a task to say "Ping from scheduler!" every 2 minutes
```

**Expected**: "Task #N scheduled. Next run: ..."

Wait 2 minutes.

**Expected**: Bot sends "Ping from scheduler!" (or similar) automatically.

```
You: List my scheduled tasks
```

**Expected**: Shows the active task.

```
You: Cancel task #N
```

**Expected**: "Task #N cancelled."

---

### Test 11: Scheduling (one-time)

```
You: At [timestamp 3 minutes from now], send me "One-shot works!"
```

**Expected**: Task is created and fires once at the specified time, then marked completed.

---

### Test 12: Mid-conversation messaging

```
You: Create 5 different files in /tmp named microclaw_1.txt through microclaw_5.txt with incrementing numbers as content, and tell me when you're done with each one
```

**Expected**: Bot may send intermediate "progress" messages via `send_message` during the multi-step operation.

---

### Test 13: Multi-chat permission model (deny path)

From a non-control chat, ask the bot to operate on another `chat_id`:

```
You: Send a message to chat_id 123456 saying "hello"
```

**Expected**: Tool call fails with a permission error.

---

### Test 14: Multi-chat permission model (allow path)

Add current chat to `control_chat_ids`, restart bot, then retry cross-chat operation.

**Expected**: Permission layer allows the operation (final success still depends on target chat reachability/tool behavior).

---

### Test 15: Long response splitting

```
You: Write a 5000-character essay about the history of computing
```

**Expected**: Response arrives in multiple chat messages (split at ~4096 char boundaries).

---

### Test 16: Group chat (requires group)

1. Add the bot to a chat group
2. Send several messages from different users without @mentioning the bot
3. Then: `@yourbotname summarize the conversation`

**Expected**: Bot reads all messages since its last reply and provides a summary.

---

### Test 17: Combined workflow

```
You: Search the web for "Rust error handling best practices", fetch the first result, and save a one-sentence summary to your memory
```

**Expected**: Bot chains web_search -> web_fetch -> write_memory -> responds with the summary.

---

### Test 18: ACP stdio mode

1. Run `microclaw acp`
2. Connect with an ACP client
3. Send one prompt, then a follow-up prompt in the same session
4. Trigger a long-running request, then send `/stop`

**Expected**: The ACP session responds normally, preserves context across turns, and `/stop` cancels the active run.

---

### Test 19: Streaming Web API

Start an async run:

```sh
curl -sS http://127.0.0.1:10961/api/send_stream \
  -H "Authorization: Bearer $MICROCLAW_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"session_key":"ops-bot","sender_name":"automation","message":"summarize the current repo"}'
```

Then connect to SSE:

```sh
curl -N "http://127.0.0.1:10961/api/stream?run_id=<RUN_ID>" \
  -H "Authorization: Bearer $MICROCLAW_API_KEY"
```

**Expected**: You see `status`, optional `tool_*`, optional `delta`, and final `done` events.

---

### Test 20: Session-native subagents

Ask the bot to delegate a multi-step task, then inspect and continue it:

```
You: Spawn a subagent to inspect the repository structure and report back
You: List my subagent runs
You: Show details for the latest subagent run
```

**Expected**: The run appears with a durable ID, progress can be inspected, and the run can be continued or cancelled.

If you hit `budget_exceeded`, raise:

```yaml
subagents:
  max_tokens_per_run: 400000
  run_timeout_secs: 1800
```

---

### Test 21: Mission Control WebSocket bridge

1. Create or reuse an operator API key with `operator.read` + `operator.write`
2. Connect to `ws://127.0.0.1:10961/`
3. Wait for `connect.challenge`
4. Send:

```json
{"type":"req","id":"connect-1","method":"connect","params":{"minProtocol":3,"maxProtocol":3,"auth":{"token":"<API_KEY>"}}}
```

5. Then send:

```json
{"type":"req","id":"send-1","method":"chat.send","params":{"sessionKey":"ops-bot","message":"summarize the current repo","idempotencyKey":"idem-1"}}
```

6. Optional: query transcript with:

```json
{"type":"req","id":"history-1","method":"chat.history","params":{"sessionKey":"ops-bot","limit":20}}
```

**Expected**: The socket receives a `res` frame for `connect`, a `res` frame for `chat.send`, then `event: chat` payloads with `delta` and `final`.

---

### Test 22: Structured memory flow

1. Send `Remember that the staging Redis endpoint is redis://127.0.0.1:6380`
2. Ask `What is the staging Redis endpoint?`
3. Open the Web UI usage or memory observability panels

**Expected**: The answer is recalled from memory, and memory observability surfaces show recent memory activity.

---

## Database Verification

After running tests, verify data was stored correctly:

```sh
sqlite3 ~/.microclaw/runtime/microclaw.db "SELECT COUNT(*) FROM messages;"
sqlite3 ~/.microclaw/runtime/microclaw.db "SELECT * FROM scheduled_tasks;"
sqlite3 ~/.microclaw/runtime/microclaw.db "SELECT * FROM chats;"
```

## Cleanup

```sh
rm -f /tmp/microclaw_test.txt /tmp/microclaw_*.txt
sqlite3 ~/.microclaw/runtime/microclaw.db "UPDATE scheduled_tasks SET status='cancelled' WHERE status='active';"
```
