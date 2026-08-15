---
id: permissions
title: Multi-Chat Permissions
sidebar_position: 5
---

MicroClaw uses a chat-scoped authorization model for tool calls.

## Model

- Non-control chats can only operate on their own `chat_id`
- Control chats can operate across chats
- Global memory writes (`write_memory` with `scope: "global"`) require control-chat privileges

Enforced tools:

- `send_message`
- Scheduler tools (`schedule_task`, `list_scheduled_tasks`, `pause_scheduled_task`, `resume_scheduled_task`, `cancel_scheduled_task`, `get_task_history`)
- `export_chat`
- `todo_read` / `todo_write`
- chat-scoped memory operations (`read_memory`/`write_memory` with `scope: "chat"`)

## Configure control chats

Add `control_chat_ids` to `microclaw.config.yaml`:

```yaml
control_chat_ids: [123456789, 987654321]
```

Then restart:

```sh
microclaw start
```

## Find chat IDs

If chats already have messages stored, query SQLite:

```sh
sqlite3 ~/.microclaw/runtime/microclaw.db \
  "SELECT chat_id, chat_title, chat_type, last_message_time FROM chats ORDER BY last_message_time DESC;"
```

Use the `chat_id` values from this output in `control_chat_ids`.

## Quick verification

From a non-control chat:

1. Ask the bot to send a message to a different `chat_id`
2. Expected: permission error

From a control chat:

1. Repeat the same cross-chat request
2. Expected: permission layer allows execution (final success depends on target chat reachability/tool behavior)

## Notes

- This is authorization at tool execution time, using trusted caller context from runtime.
- It does not sandbox host command/file access by itself. Keep host deployment locked down.
- To inspect sandbox posture and execution policy state in Web UI, open Settings and run config self-check (Security posture card).
