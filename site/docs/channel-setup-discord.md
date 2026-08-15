---
id: channel-setup-discord
title: Channel Setup - Discord
---

## Official Links

- [Discord Developer Portal](https://discord.com/developers/applications)
- [Discord developer docs](https://discord.com/developers/docs/intro)
- [Privileged intents docs](https://discord.com/developers/docs/topics/gateway#privileged-intents)

## Token Provisioning

1. Create a Discord application.
2. Add a Bot under **Bot**.
3. Copy bot token (**Reset Token** if needed).
4. In **OAuth2 -> URL Generator**, select scopes `bot` and `applications.commands`.
5. Grant minimum permissions: `View Channels`, `Send Messages`, `Read Message History`.
6. Open generated URL and invite bot to your target server.
7. Enable **Message Content Intent** under **Bot -> Privileged Gateway Intents**.

## Account-based Setup

```yaml
channels:
  discord:
    enabled: true
    default_account: "main"
    accounts:
      main:
        enabled: true
        bot_token: "DISCORD_TOKEN_MAIN"
      ops:
        enabled: true
        bot_token: "DISCORD_TOKEN_OPS"
        # Optional: reply without mention in guild channels
        no_mention: true
        # Optional per-account channel allowlist
        # allowed_channels: [123456789012345678]
```

Notes:

- Each token maps to one Discord bot application.
- If `MESSAGE_CONTENT` is disabled, guild message handling will be limited.

## Verify

1. `microclaw start`
2. Mention bot in guild channel: `@bot /skills`
3. Validate each configured account.

## Quick Troubleshooting

- Online but silent: verify bot permissions and mention behavior.
- `4014 Disallowed intent(s)`: enable Message Content Intent and restart.
