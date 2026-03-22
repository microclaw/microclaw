# OpenClaw Weixin Bridge

MicroClaw does not execute OpenClaw channel plugins directly. `@tencent-weixin/openclaw-weixin` depends on the OpenClaw plugin runtime, so the supported MicroClaw pattern is a sidecar bridge:

1. Run the Weixin login + long-poll logic in a separate Node process.
2. Forward inbound Weixin messages into MicroClaw over a webhook.
3. Let MicroClaw send outbound replies back through a configured `send_command`.

This document describes the MicroClaw side of that contract.

## Config

Single-account example:

```yaml
channels:
  openclaw-weixin:
    enabled: true
    webhook_path: /openclaw-weixin/messages
    webhook_token: replace-me
    send_command: node /opt/weixin-bridge/send.mjs
    allowed_user_ids: "alice@im.wechat,bob@im.wechat"
```

Multi-account example:

```yaml
channels:
  openclaw-weixin:
    enabled: true
    default_account: main
    accounts:
      main:
        send_command: node /opt/weixin-bridge/send-main.mjs
      ops:
        send_command: node /opt/weixin-bridge/send-ops.mjs
        webhook_token: replace-me-ops
```

## Inbound Webhook

Send `POST` requests to the configured `webhook_path`.

Headers:

- `Content-Type: application/json`
- `x-openclaw-weixin-webhook-token: <token>` when `webhook_token` is configured
- `Authorization: Bearer <token>` is also accepted as a fallback

Body:

```json
{
  "account_id": "main",
  "from_user_id": "alice@im.wechat",
  "text": "hello",
  "message_id": "wx-msg-123",
  "timestamp_ms": 1740000000000,
  "context_token": "ctx-123"
}
```

Fields:

- `account_id`: optional for single-account mode; selects `channels.openclaw-weixin.accounts.<id>`.
- `from_user_id`: required Weixin user id.
- `text`: required plain-text content forwarded into the agent loop.
- `message_id`: optional dedupe key.
- `timestamp_ms` or `timestamp`: optional startup-guard timestamp.
- `context_token`: strongly recommended and required for later replies to the same user.

MicroClaw also accepts a more upstream-like nested shape:

```json
{
  "account_id": "main",
  "message": {
    "from_user_id": "alice@im.wechat",
    "message_id": 42,
    "create_time_ms": 1740000000000,
    "context_token": "ctx-123",
    "item_list": [
      { "type": 1, "text_item": { "text": "hello" } }
    ]
  }
}
```

For `item_list`, MicroClaw currently normalizes:

- text -> plain text
- voice with transcript -> transcript text
- image -> `[image]`
- file -> `[file]` or `[file: <name>]`
- video -> `[video]`

## Outbound Command Contract

MicroClaw executes `send_command` with `sh -lc`.

Environment variables:

- `MICROCLAW_WEIXIN_ACTION`: `send_text` or `send_attachment`
- `MICROCLAW_WEIXIN_CHANNEL_NAME`: resolved MicroClaw channel name
- `MICROCLAW_WEIXIN_ACCOUNT_ID`: selected account id, or empty in single-account mode
- `MICROCLAW_WEIXIN_TARGET`: Weixin user id
- `MICROCLAW_WEIXIN_TEXT`: outbound text
- `MICROCLAW_WEIXIN_CONTEXT_TOKEN`: cached context token for that user
- `MICROCLAW_WEIXIN_ATTACHMENT_PATH`: attachment path for `send_attachment`
- `MICROCLAW_WEIXIN_ATTACHMENT_CAPTION`: optional attachment caption
- `MICROCLAW_WEIXIN_PAYLOAD`: JSON bundle containing the same fields

Example payload:

```json
{
  "action": "send_text",
  "channel_name": "openclaw-weixin",
  "account_id": "main",
  "target": "alice@im.wechat",
  "text": "hello",
  "context_token": "ctx-123",
  "attachment_path": "",
  "attachment_caption": ""
}
```

If you want a minimal starting point, use:

```yaml
send_command: WEIXIN_BRIDGE_URL=http://127.0.0.1:8788/send WEIXIN_BRIDGE_TOKEN=replace-me node examples/openclaw-weixin/send-command-http-forward.mjs
```

That helper simply forwards `MICROCLAW_WEIXIN_PAYLOAD` to your local sidecar over HTTP.

## Context Token Behavior

Weixin replies require a `context_token`. MicroClaw caches the latest token per `channel + user`.

Implications:

- A user must send at least one inbound message before MicroClaw can reply through `send_command`.
- Scheduled or proactive delivery to a never-seen Weixin user will fail until the bridge has posted one inbound webhook carrying a `context_token`.

## Using `@tencent-weixin/openclaw-weixin`

The npm package can still provide the Node-side login and long-polling flow. The bridge only needs to translate:

- package inbound updates -> MicroClaw webhook payload above
- MicroClaw `send_command` env payload -> package send-message logic

Starter files:

- `examples/openclaw-weixin/README.md`
- `examples/openclaw-weixin/send-command-http-forward.mjs`

The package metadata and protocol description live at:

- npm: `https://www.npmjs.com/package/@tencent-weixin/openclaw-weixin`
- registry metadata: `https://registry.npmjs.org/@tencent-weixin/openclaw-weixin`
