---
id: faq
title: FAQ
sidebar_position: 14
---

## Is MicroClaw production-ready?

Yes. Review the security model and run it on a locked-down host for production deployments.

## Does it support images, voice, or files?

Telegram supports text + images + document uploads. Voice messages are transcribed when `openai_api_key` is configured.  
For tool-driven outbound attachments, `send_message` supports Telegram / Discord / Slack / Weixin via `attachment_path` (+ optional `caption`).

## Can I restrict who can run commands?

Yes. Configure `control_chat_ids` in `microclaw.config.yaml`:

- non-control chats can only operate on their own `chat_id`
- control chats can perform cross-chat actions
- global memory writes are limited to control chats

## How does memory work?

Memory is stored in `AGENTS.md` files under `~/.microclaw/runtime/groups/` by default (or under your configured `data_dir`) and injected into the system prompt for every request. There are three scopes: global (`groups/AGENTS.md`), bot/account (`groups/{channel}/AGENTS.md`), and chat (`groups/{channel}/{chat_id}/AGENTS.md`).

## How do scheduled tasks work?

The scheduler polls every 60 seconds for due tasks, runs the same agent loop as normal messages, sends the result, and updates the next run time.

## Can I add custom tools?

Yes. Implement the `Tool` trait (`microclaw_tools::runtime::Tool`) in `src/tools/`, register it in `ToolRegistry::new()`, and it becomes available to the LLM automatically.

## What model is used by default?

`model` defaults to a provider-specific value (`claude-sonnet-4-5-20250929` for `anthropic`, `gpt-5.2` for `openai`, `gpt-5.3-codex` for `openai-codex`, `llama3.2` for `ollama`).  
You can override it in `microclaw.config.yaml`.
