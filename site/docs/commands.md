---
id: commands
title: Slash Commands
sidebar_position: 6
---

MicroClaw supports the following slash commands in chat channels.

Supported channels: Telegram, Discord, Slack, Feishu/Lark, IRC.

## Commands

| Command | Description |
|---|---|
| `/clear` | Clear current chat context (session + chat history) but keep scheduled tasks for that chat. |
| `/reset` | Clear current chat context (session + chat history) and remove scheduled tasks for that chat. |
| `/reset memory` | Clear current chat memory (chat AGENTS.md + structured memories) without clearing conversation or tasks. |
| `/stop` | Abort the active run in the current chat. Does not clear session or chat history. |
| `/skills` | List all currently available skills discovered by runtime. |
| `/rewind` | List the most recent filesystem checkpoints for the current chat (newest first). Requires `checkpoints_enabled: true`. |
| `/rewind <commit>` | Restore the chat's working directory to the given checkpoint hash. Hash must be 4–64 hex chars. |
| `/reload-skills` | Reload skills from disk and return the reloaded count. |
| `/archive` | Archive current in-memory session as a markdown conversation file. |
| `/usage` | Show usage and memory observability summary for current chat. |
| `/status` | Show current provider/model (effective for this bot account) and current-chat status summary. |
| `/providers` | List configured provider profiles and indicate the active one. |
| `/provider` | Show current provider/model. `/provider <profile>` switches the current bot account to that provider profile and persists it to config. `/provider reset` clears the current bot account override. |
| `/models` | List configured models for the active provider. `/models api` fetches the live provider model list when supported. |
| `/model` | Show current provider/model. `/model <name>` switches the current bot account model override and persists it to config. `/model reset` clears the current bot account override. |

## Notes

- Any input starting with `/` is treated as a command.
- Inputs with leading mentions before slash are also treated as commands (for example `@bot /status`, `<@U123> /status`).
- Commands are matched exactly (for example, `/reset`).
- Chat commands such as `/reset`, `/clear`, `/stop`, `/usage`, and `/archive` are scoped to the current chat conversation.
- `/provider` and `/model` are scoped to the current bot account, not all bots on the same channel type.
- Slash command inputs are not appended to agent conversation history/session context.
- Unknown slash commands return `Unknown command.`.
- `/stop` only aborts in-flight work for the current chat; it does not clear context.
- In group/server/channel chats, slash commands are mention-gated by default.
- To disable mention-gating for group slash commands, set `allow_group_slash_without_mention: true`.
- `/archive` is manual; automatic archive may also happen before context compaction.
- `/provider` and `/model` changes are persisted into `microclaw.config.yaml` for the current bot/account, so they survive restart.
