---
id: channel-setup-weixin
title: Channel Setup - Weixin
---

## Native Channel

Weixin runs natively in Rust. No Node sidecar or `@tencent-weixin/openclaw-weixin` package is required.

## Minimal Config

The default setup only needs this:

```yaml
channels:
  weixin:
    enabled: true
```

`microclaw setup` fills in the default Weixin endpoints automatically:

- `https://ilinkai.weixin.qq.com`
- `https://novac2c.cdn.weixin.qq.com/c2c`

You normally do not need to edit them manually.

## Login

Run:

```bash
microclaw weixin login
```

MicroClaw prints a QR link and renders the QR code in the terminal when the terminal supports it.

Useful commands:

```bash
microclaw weixin status
microclaw weixin logout
```

## Runtime State

By default, Weixin state is stored under:

- `~/.microclaw/runtime/weixin/accounts/<account>.json`
- `~/.microclaw/runtime/weixin/sync/<account>.txt`

If you override `data_dir`, the effective path becomes `<data_dir>/runtime/weixin/...`.

## Start And Verify

1. Run `microclaw weixin login` and scan the QR code.
2. Start MicroClaw with `microclaw start`.
3. Send a Weixin message to the linked account.
4. Verify that MicroClaw receives the inbound message and replies.

## Notes

- Weixin replies require a cached `context_token`, so MicroClaw cannot proactively message a user it has never seen before.
- Native outbound delivery supports text, images, videos, and generic file attachments.
- Optional advanced config such as `allowed_user_ids`, `webhook_token`, per-account overrides, and `provider_preset` can still be added in `microclaw.config.yaml`.
