---
id: channel-setup-feishu-lark
title: Channel Setup - Feishu / Lark
---

## Official Links

- [Feishu Open Platform](https://open.feishu.cn/app)
- [Lark Developer](https://open.larksuite.com/app)
- [Feishu docs center](https://open.feishu.cn/document/)
- [Lark docs center](https://open.larksuite.com/document/)

## Credential Provisioning

1. Create custom app.
2. Copy `App ID` and `App Secret`.
3. Add permissions/scopes needed for bot messaging.
4. Configure event mode:
   - local/dev: **Long Connection (websocket)**
   - public endpoint: **Webhook**
5. Add receive-message event subscriptions.
6. Publish and approve app per org policy.

## Account-based Setup

Use one or more app credentials as accounts:

```yaml
channels:
  feishu:
    enabled: true
    default_account: "main"
    accounts:
      main:
        enabled: true
        app_id: "cli_xxx"
        app_secret: "xxx"
        domain: "feishu"
        topic_mode: true          # optional; reply in thread for this bot
      intl:
        enabled: true
        app_id: "cli_yyy"
        app_secret: "yyy"
        domain: "lark"
        topic_mode: true          # optional; reply in thread for this bot
        # Optional per-account chat filter
        # allowed_chats: ["oc_xxx"]
```

Notes:

- For international tenants, set `domain: "lark"`.
- `topic_mode` is bot/account-level (`accounts.<id>.topic_mode`), not channel-level.
- `topic_mode` is only supported when account `domain` is `feishu` or `lark`.
- Webhook mode needs public ingress; websocket mode does not.
- Emoji reaction reply is supported:
  - If the model final response is a single emoji/emoji token (for example `👍`, `:thumbsdown:`, `TearsofJoy`), MicroClaw sends Feishu reaction on the original message.
  - Supports direct `emoji_type` values and common aliases/emoji characters (including Chinese aliases like `点赞`).
  - For finer control, model output can use:
    - `reaction-only: <emoji-or-token>` for reaction only.
    - `reaction: <emoji-or-token>` + newline + reply text for reaction + text.
    - `[reaction: <emoji-or-token>] <reply text>` as inline form.
  - If reaction send fails:
    - implicit single-token reaction output falls back to plain text.
    - explicit `reaction-only:` keeps silent text-wise (no forced text reply).

### Emoji Type List & Meaning Guide

- Full supported `emoji_type` set is maintained in code: `src/channels/feishu.rs` (`FEISHU_EMOJI_TYPES`).
- Current built-in list size: **254** emoji types.
- The bot can choose any supported `emoji_type` directly (for example `THUMBSUP`, `PARTY`, `ROCKET`).
- No fixed meaning mapping is enforced.
- To reduce unsupported selections, prompt guidance constrains model selection to a supported whitelist (for example: `THUMBSUP`, `THUMBSDOWN`, `CLAP`, `THANKS`, `HEART`, `BROKENHEART`, `Fire`, `PARTY`, `SMILE`, `TearsofJoy`, `SOB`, `RAGE`, `FISTBUMP`, `ROCKET`, `100`, `LetMeSee`, `OK`, `LOVE`, `HAPPY`, `WINK`, `YEAH`, `STRONG`, `TOP`, `NO1`).

## Verify

1. `microclaw start`
2. DM each bot `/skills`
3. Confirm replies in intended chats.
