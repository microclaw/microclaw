---
id: channel-setup-slack
title: Channel Setup - Slack
---

## Official Links

- [Slack app dashboard](https://api.slack.com/apps)
- [Socket Mode guide](https://api.slack.com/apis/connections/socket)
- [OAuth scopes reference](https://api.slack.com/scopes)
- [Event subscriptions](https://api.slack.com/apis/connections/events-api)

## Token Provisioning

1. Create app from scratch in target workspace.
2. Enable **Socket Mode**.
3. Create app token (`xapp-...`) with `connections:write`.
4. Under **OAuth & Permissions**, add bot scopes:
   - `chat:write`
   - `channels:history`
   - `groups:history`
   - `im:history`
   - `mpim:history`
   - `app_mentions:read`
5. Install app to workspace and copy bot token (`xoxb-...`).
6. Enable events and add bot events:
   - `message.channels`
   - `message.groups`
   - `message.im`
   - `message.mpim`
   - `app_mention`

## Account-based Setup

```yaml
channels:
  slack:
    enabled: true
    default_account: "main"
    accounts:
      main:
        enabled: true
        bot_token: "xoxb-main..."
        app_token: "xapp-main..."
      support:
        enabled: true
        bot_token: "xoxb-support..."
        app_token: "xapp-support..."
        # Optional per-account channel filter
        # allowed_channels: ["C123ABC456"]
```

Notes:

- One bot identity = one `xoxb` + one `xapp` pair.
- Multi-account is useful for env separation (`prod`, `staging`, `support`).

## Verify

1. `microclaw start`
2. DM each bot `/skills`
3. Test `@mention` in allowed channels.
