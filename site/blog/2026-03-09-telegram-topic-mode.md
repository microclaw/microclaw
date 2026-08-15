---
slug: /telegram-topic-mode
title: "Telegram Topic Mode: One Group, Clean Session Boundaries"
authors: [microclaw]
tags: [telegram, channels, runtime]
---

Telegram forum groups are useful until every thread shares one agent memory buffer.

MicroClaw's Telegram topic mode fixes that by routing each forum topic as its own chat session, while still replying inside the original Telegram thread.

<!-- truncate -->

## What topic mode does

When `channels.telegram.topic_routing.enabled` is on, MicroClaw stores a topic message with:

```text
external_chat_id=<chat_id>:<thread_id>
```

That small routing change matters because it gives each topic:

- its own session history
- its own memory and resumable context
- its own focused sub-agent binding when subagents are in use

Without topic routing, a busy support forum or operator room can blur multiple workstreams into one long conversation.

## Why this is the right default for forum-style groups

Telegram topics are already a user-facing isolation model. The runtime should match that model.

With topic mode enabled, you can treat one Telegram supergroup like a bundle of small task rooms:

- one topic for release ops
- one topic for customer incidents
- one topic for code review follow-ups
- one topic for experiments or scratch work

The bot keeps replies inside the same topic by preserving `message_thread_id` on outbound messages, so the user experience still feels native to Telegram.

## Configuration

Channel-wide:

```yaml
channels:
  telegram:
    enabled: true
    topic_routing:
      enabled: true
```

Per-account override in multi-bot mode:

```yaml
channels:
  telegram:
    default_account: "main"
    topic_routing:
      enabled: false
    accounts:
      main:
        enabled: true
        bot_token: "123456:ABC..."
        bot_username: "main_bot"
      support:
        enabled: true
        bot_token: "987654:XYZ..."
        bot_username: "support_bot"
        topic_routing:
          enabled: true
```

That lets one bot stay topic-aware while another keeps legacy group behavior.

## Where it helps immediately

### 1. Support and triage groups

Each customer issue can live in its own topic instead of fighting for one shared context window.

### 2. Multi-bot operations

MicroClaw already supports multiple Telegram bot accounts in one runtime. Topic mode keeps each bot's thread-local work cleaner in shared operator groups.

### 3. Long-running tasks

A topic can become the stable home for a single ongoing effort, such as release prep or a debugging session, without contaminating unrelated chats.

## Practical behavior

Once enabled:

- replies in different topics no longer share the same `external_chat_id`
- session resume works per topic
- structured memory extraction sees topic conversations as separate chat streams
- follow-up work lands back in the same Telegram thread

This is one of those changes that looks small in config but removes a lot of operational noise in practice.

## Docs

- [Telegram setup](/docs/channel-setup-telegram)
- [Configuration reference](/docs/configuration)
- [Quickstart](/docs/quickstart)
