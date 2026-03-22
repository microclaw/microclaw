# OpenClaw Weixin Bridge Examples

This folder contains starter pieces for wiring a Weixin sidecar into MicroClaw.

Files:

- `send-command-http-forward.mjs`
  - Example `channels.openclaw-weixin.send_command` target.
  - Reads `MICROCLAW_WEIXIN_PAYLOAD` from MicroClaw and forwards it to a local HTTP bridge.

Typical config:

```yaml
channels:
  openclaw-weixin:
    enabled: true
    webhook_path: /openclaw-weixin/messages
    webhook_token: replace-me
    send_command: WEIXIN_BRIDGE_URL=http://127.0.0.1:8788/send WEIXIN_BRIDGE_TOKEN=replace-me node examples/openclaw-weixin/send-command-http-forward.mjs
```

The sidecar behind `WEIXIN_BRIDGE_URL` is responsible for turning that JSON payload into the real Weixin send API call or into `@tencent-weixin/openclaw-weixin` runtime calls.

See also:

- `docs/operations/openclaw-weixin-bridge.md`
