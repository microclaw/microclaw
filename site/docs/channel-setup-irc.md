---
id: channel-setup-irc
title: Channel Setup - IRC
---

## Official Links

- [IRC protocol RFC 1459](https://www.rfc-editor.org/rfc/rfc1459)
- [Example network docs (Libera.Chat)](https://libera.chat/guides/connect)

## Server Provisioning

1. Confirm IRC host/port and auth requirements.
2. Reserve bot nick.
3. Choose channels to auto-join (comma-separated).
4. If required, prepare TLS settings.

## Single-bot Setup

IRC currently does not use API tokens.

```yaml
channels:
  irc:
    enabled: true
    server: "irc.example.com"
    port: "6667"
    nick: "microclaw"
    channels: "#general,#ops"
    # Optional
    # username: "microclaw"
    # real_name: "MicroClaw"
    # password: ""
    # mention_required: "true"
    # tls: "false"
    # tls_server_name: ""
    # tls_danger_accept_invalid_certs: "false"
```

## Multi-token Multi-bot

Native `channels.irc.accounts` is not available in current baseline.

Recommended approach:

1. Run multiple MicroClaw instances.
2. Give each instance a unique `nick` and config file.
3. Split channel coverage by process.

## Verify

1. `microclaw start`
2. Mention bot in channel and send `/skills`
3. Confirm mention-triggered reply.
