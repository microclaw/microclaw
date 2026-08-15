---
id: channel-setup
title: Channel Setup
sidebar_position: 4
---

This section provides detailed setup guides per channel.

## What You Will Get

Each channel guide includes:

- token/credential provisioning
- account-based bot setup
- multi-bot setup
- QR login where applicable
- verification checklist
- official external links

## Channel Guides

- [Telegram](./channel-setup-telegram)
- [Discord](./channel-setup-discord)
- [Slack](./channel-setup-slack)
- [Feishu / Lark](./channel-setup-feishu-lark)
- [Weixin](./channel-setup-weixin)
- [IRC](./channel-setup-irc)

## Web UI

Web UI does not require token or bot-account setup.
Web UI operator auth uses password login.

Use normal startup and open your local web address from runtime logs.

```bash
microclaw start
```

Default local address:

- `http://127.0.0.1:10961`

Web password notes:

- If no operator password exists, MicroClaw initializes a temporary default password: `helloworld`.
- After signing in, the UI prompts you to change the default password (you can skip temporarily).
- CLI helpers:
  - `microclaw web` (show usage)
  - `microclaw web password <value>`
  - `microclaw web password-generate`
  - `microclaw web password-clear`

## Before You Start

1. Prepare `microclaw.config.yaml`.
2. Configure LLM keys (`llm_provider`, `api_key`, `model`).
3. If channel/bot-specific LLM routing is needed, define reusable `provider_presets` profiles and point `channels.<name>.provider_preset` or `channels.<name>.accounts.<id>.provider_preset` at them.
4. Restart MicroClaw after channel config changes.
