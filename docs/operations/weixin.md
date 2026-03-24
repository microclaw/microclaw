# Weixin

MicroClaw now supports Weixin as a native Rust channel. No Node sidecar or `@tencent-weixin/openclaw-weixin` bridge is required for login, polling, text replies, or attachment replies.

Native support includes:

- QR login
- persisted bot credentials
- long polling via `getupdates`
- native typing indicator via `getconfig` + `sendtyping`
- persisted `context_token` cache
- persisted `get_updates_buf`
- text replies via `sendmessage`
- image, video, and file attachment replies via native CDN upload

## Quick Start

The default setup only needs Weixin to be enabled:

```yaml
channels:
  weixin:
    enabled: true
```

`microclaw setup` writes the default Weixin endpoints automatically:

- `base_url: https://ilinkai.weixin.qq.com`
- `cdn_base_url: https://novac2c.cdn.weixin.qq.com/c2c`

For a normal single-account deployment, you do not need to set them manually.

Then login once:

```sh
microclaw weixin login
```

Then start MicroClaw:

```sh
microclaw start
```

By default, native Weixin runtime state is stored under:

- `~/.microclaw/runtime/weixin/accounts/<account>.json`
- `~/.microclaw/runtime/weixin/sync/<account>.txt`

If you override `data_dir`, the effective path becomes `<data_dir>/runtime/weixin/...`.

## Optional Advanced Config

Single-account example with overrides:

```yaml
channels:
  weixin:
    enabled: true
    allowed_user_ids: "alice@im.wechat,bob@im.wechat"
```

Multi-account example:

```yaml
channels:
  weixin:
    enabled: true
    default_account: main
    accounts:
      main:
        allowed_user_ids: "alice@im.wechat"
      ops:
        webhook_token: replace-me-ops
        allowed_user_ids: "ops-user@im.wechat"
```

Supported optional overrides:

- `base_url`
- `cdn_base_url`
- `allowed_user_ids`
- `webhook_token`
- `bot_username`
- `model`
- `provider_preset`
- `webhook_path`

## Native CLI

Login and persist credentials:

```sh
microclaw weixin login
microclaw weixin login --account ops
microclaw weixin login --account ops --base-url https://ilinkai.weixin.qq.com
```

Inspect local state:

```sh
microclaw weixin status
microclaw weixin status --account ops
```

Remove local credentials and sync cursor:

```sh
microclaw weixin logout
microclaw weixin logout --account ops
```

## Runtime Behavior

- Polling starts automatically on `microclaw start` once credentials exist for that account.
- During agent execution, MicroClaw sends native Weixin typing keepalives when a `typing_ticket` is available.
- Replying requires a previously seen `context_token`, so proactive sends to a never-seen user are not possible yet.
- Outbound native delivery supports text, image, video, and generic file attachments.
- If login has not been completed yet, runtime startup keeps the adapter idle and prints a warning until `microclaw weixin login` is run.

## Inbound Webhook

The native runtime uses long polling, but MicroClaw still accepts compatible webhook payloads for interoperability or controlled external forwarding.

Send `POST` requests to the configured `webhook_path` when you explicitly enable webhook forwarding.

Headers:

- `Content-Type: application/json`
- `x-weixin-webhook-token: <token>` when `webhook_token` is configured
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

## Context Token Behavior

Weixin replies require a `context_token`. MicroClaw caches the latest token per `channel + user`.

Implications:

- A user must send at least one inbound message before MicroClaw can reply.
- Scheduled or proactive delivery to a never-seen Weixin user will fail until MicroClaw has seen one inbound message carrying a `context_token`.
