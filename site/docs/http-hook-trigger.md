---
id: http-hook-trigger
title: HTTP Hook Trigger
sidebar_position: 7
---

This page documents the webhook-style HTTP trigger surface for external automation.

Use this when you want CI jobs, webhook handlers, or cron scripts to trigger MicroClaw runs without opening Web UI.

## Endpoints

- `POST /hooks/agent`
- `POST /api/hooks/agent` (alias)
- `POST /hooks/wake`
- `POST /api/hooks/wake` (alias)

## Hook Authentication

`/hooks/*` endpoints use a dedicated token from `channels.web.hooks_token`.

Accepted auth headers:

- `Authorization: Bearer <token>` (recommended)
- `x-openclaw-token: <token>`
- `x-microclaw-hook-token: <token>`

## Configuration

```yaml
channels:
  web:
    hooks_token: "replace-with-secret"
    hooks_default_session_key: "hook:ingress"
    hooks_allow_request_session_key: false
    hooks_allowed_session_key_prefixes: ["hook:"]
```

### Session key policy

- By default, request `sessionKey` is blocked (`hooks_allow_request_session_key: false`).
- If enabled, `hooks_allowed_session_key_prefixes` can restrict allowed values.
- If request `sessionKey` is missing, MicroClaw uses `hooks_default_session_key`.

## `POST /hooks/agent`

OpenClaw-style payload shape is supported:

```json
{
  "message": "Summarize inbox",
  "name": "Email",
  "sessionKey": "hook:email:msg-123"
}
```

Behavior:

- `message` is required.
- `name` is optional and used as sender fallback.
- accepted requests start an async run and return `run_id`.

Use `GET /api/stream?run_id=<id>` to consume events.

## `POST /hooks/wake`

Payload:

```json
{
  "text": "New email received",
  "mode": "now"
}
```

- `text` is required.
- `mode` is optional:
  - `now` (default): starts async run immediately.
  - `next-heartbeat`: queues a system-event message only.

## Examples

```bash
curl -sS http://127.0.0.1:10961/hooks/agent \
  -H "Authorization: Bearer $MICROCLAW_HOOKS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message":"Summarize inbox","name":"Email"}'
```

```bash
curl -sS http://127.0.0.1:10961/hooks/wake \
  -H "Authorization: Bearer $MICROCLAW_HOOKS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"text":"New email received","mode":"next-heartbeat"}'
```

## Troubleshooting

- `401 unauthorized`: missing or invalid hook token.
- `503 hooks token is not configured`: set `channels.web.hooks_token`.
- `400 sessionKey override is disabled`: request passed `sessionKey` while overrides are off.
- `400 sessionKey is not allowed by configured prefixes`: request key failed prefix policy.
