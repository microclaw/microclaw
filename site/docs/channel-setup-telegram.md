---
id: channel-setup-telegram
title: Channel Setup - Telegram
---

## Official Links

- [BotFather](https://t.me/BotFather)
- [Telegram Bot API docs](https://core.telegram.org/bots/api)
- [Privacy mode (`/setprivacy`)](https://core.telegram.org/bots/features#privacy-mode)

## Token Provisioning

1. Open BotFather and run `/newbot`.
2. Set bot display name and username (must end with `bot`).
3. Copy the HTTP API token (`123456:ABC...`).
4. Optional for group behavior: run `/setprivacy` and tune as needed.

## Account-based Setup

```yaml
channels:
  telegram:
    enabled: true
    default_account: "main"
    # Optional: treat each Telegram topic/thread as an isolated chat
    topic_routing:
      enabled: true
    accounts:
      main:
        enabled: true
        bot_token: "123456:ABC-DEF1234..."
        bot_username: "my_microclaw_main_bot"
      support:
        enabled: true
        bot_token: "987654:XYZ-DEF9999..."
        bot_username: "my_microclaw_support_bot"
        # Optional per-account override (falls back to channels.telegram.topic_routing.enabled)
        # topic_routing:
        #   enabled: false
        # Optional per-account group allowlist
        # allowed_groups: [-1001234567890]
        # Optional per-account DM sender allowlist (Telegram user IDs)
        # allowed_user_ids: [123456789]
```

Notes:

- Each account runs as an independent Telegram bot in the same MicroClaw process.
- `bot_username` must not include `@`.
- Mention the specific bot username that should answer in group chats.
- When topic routing is enabled, topic messages are persisted with `external_chat_id=<chat_id>:<thread_id>` so each topic keeps an independent session.
- For group chats with multi-token multi-bot, configure each bot in BotFather:
  - `Bot Settings -> Allow Groups`: enabled
  - `Bot Settings -> Group Privacy`: disabled (`/setprivacy` -> `Disable`)

## Verify

1. `microclaw start`
2. DM each bot: `/skills`
3. In a group, mention each bot and verify replies.

## Quick Troubleshooting

- Bot replies in DM but not group: check mention and privacy mode.
- Token rotated in BotFather: update token and restart MicroClaw.
