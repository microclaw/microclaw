# Local Web UI and Gateway

MicroClaw serves a local management UI and API when `web_enabled: true`. The default address is:

```text
http://127.0.0.1:10961
```

The UI reads sessions from the same SQLite store used by chat channels. It can create Web sessions, inspect cross-channel history, clear context, manage tasks and settings, and show governance and learning state. Sessions originating on non-Web channels remain read-only in the Web UI by default.

## First sign-in

If no operator password exists, MicroClaw initializes a temporary password and asks you to replace it after sign-in. Manage the password from the CLI:

```sh
microclaw web
microclaw web password <value>
microclaw web password-generate
microclaw web password-clear
```

Changing or clearing the password revokes existing Web login sessions.

## Bind address and exposure

The default loopback bind is intended for local access. Before binding to a non-loopback interface:

1. Set a strong operator password and scoped API keys.
2. Put TLS and appropriate network access control in front of the service.
3. Review the [secure runtime](../security/secure-runtime.md) and [Web security audit](../security/audit-2026-07-web-ui-clawhub.md).
4. Keep hook tokens separate from operator API keys.

Relevant top-level settings include `web_enabled`, `web_host`, and `web_port`. Use the [generated config defaults](../generated/config-defaults.md) and [`microclaw.config.example.yaml`](../../microclaw.config.example.yaml) for current values.

## HTTP, SSE, and hooks

The Web surface supports synchronous chat, asynchronous runs with SSE replay, and OpenClaw-compatible hooks. The canonical operations guide for payloads, authentication, session routing, and curl examples is [HTTP request triggers](http-hook-trigger.md).

Common entry points include:

- `POST /api/send` for a synchronous run
- `POST /api/send_stream` for an asynchronous run
- `GET /api/stream?run_id=<id>` for SSE replay
- `POST /hooks/agent` for an authenticated agent hook
- `POST /hooks/wake` for a system-event wake trigger

Web API calls that mutate state require an API key with the appropriate scope. `/hooks/*` uses the dedicated `channels.web.hooks_token` setting and rejects requests when no hook token is configured.

## MicroClaw Code: notifications and approvals in chat

A paired MicroClaw Code (`mccode remote pair`) can reach you in a chat app
while you are away from the terminal. The endpoints take the device token (or
any API key) as `Authorization: Bearer …`; sending needs `operator.write`.
The chat is written `<channel>:<chat id>`, using the channel name from the
config (`telegram`, `telegram.<account>`, `discord`, `slack`, `feishu`, …)
and the chat id the platform uses (Telegram chat id, Discord channel id,
Slack channel id, Feishu `chat_id`).

| Endpoint | Body / result |
| --- | --- |
| `POST /api/code/notify` | `{"chat": "telegram:123", "text": "…", "title": "…"}` (title optional) → `{"ok": true, "delivery": "delivered" \| "queued"}`. Uses the normal delivery path, so a failed send is retried from the outbox. |
| `POST /api/code/approvals` | `{"chat", "title", "text", "options": [{"value": "approve", "label": "Approve once"}, …], "ttl_secs": 1800}` (1–5 options; `ttl_secs` defaults to 30 min, clamped to 30 s–24 h) → `{"ok": true, "id", "status": "pending", "expires_at", …}` |
| `GET /api/code/approvals/:id` | `{"status": "pending" \| "answered" \| "expired" \| "cancelled", "value", "label", "answered_by", "expires_at", "finished_at"}` |
| `DELETE /api/code/approvals/:id[?reason=…]` | Cancels a pending approval and edits the card to say it was answered in the terminal (`{"cancelled": true}`; `false` when it was already finished). |

Errors: `400` for a malformed body, a disabled channel or a channel without
approval support; `404` for a chat the Server has never seen (send the bot a
message from it first) or an approval id that is unknown or belongs to
another caller; `403` when an approval targets a chat that is not a control
chat; `502` when the channel send fails.

How answers come back:

- Telegram, Discord and Slack show the options as buttons. Their callback
  data is `mcc:<id>:<n>`, separate from the agent's own `apv:` approval
  buttons, so a tap on one can never answer the other.
- On every supported channel (Telegram, Discord, Slack, Feishu/Lark) a text
  reply with the option's number, value or label in the card's chat answers
  the newest pending card there; the reply is not passed to the agent. Any
  other message goes to the agent as usual. In Telegram groups with privacy
  mode on, reply to the card (or tap) so the bot sees the message.
- Pending approvals are kept in memory: a Server restart drops them and the
  client reports them as gone.

Rules:

- Approval cards only go to chats listed in `control_chat_ids`. Notifications
  may go to any chat the Server already knows on an enabled channel.
- An answer counts only when it comes from the chat (or a thread/topic in it)
  that received the card; a tap carrying the same callback data in another
  chat is rejected.
- The channel's own inbound checks still apply: Telegram `allowed_user_ids`
  (when set, only those users can answer, in groups too), Discord/Slack
  `allowed_channels`, Feishu `allowed_chats`.
- Only the device or key that created an approval (or an admin key) can read
  or cancel it.

## WebSocket gateway

The OpenClaw Mission Control-compatible bridge upgrades WebSocket connections at `GET /`.

The basic handshake is:

1. Connect to `ws://127.0.0.1:10961/`.
2. Wait for `connect.challenge`.
3. Send a `connect` request with the operator API key in `params.auth.token`.
4. Use bridge methods such as `chat.send`, `chat.history`, `sessions.list`, `sessions.send`, `sessions.spawn`, `sessions.kill`, `models.list`, and `config.get`.
5. Consume `chat` events until a terminal `final` or `error` event arrives.

For a quick local check:

```sh
MICROCLAW_GATEWAY_TOKEN=mc_... microclaw gateway call health
MICROCLAW_GATEWAY_TOKEN=mc_... microclaw gateway call status
```

Connection settings can be supplied with `MICROCLAW_GATEWAY_URL`, `MICROCLAW_GATEWAY_HOST`, `MICROCLAW_GATEWAY_PORT`, and `MICROCLAW_GATEWAY_TOKEN`. OpenClaw-compatible aliases are also supported.

## Concurrency behavior

Web streamed runs, scheduled jobs, reflector passes, and session-native subagents use separate async lanes. Each chat still serializes turns, while safe read-only tool calls can run in parallel waves inside a turn. Mid-turn user messages can be injected into the active loop when enabled.

See [Concurrency and responsiveness](concurrency-and-responsiveness.md) for limits and tuning.

## Browser smoke test

`web/e2e/` holds a small Playwright suite that runs against the real embedded
bundle rather than a Vite dev server. It boots `microclaw start` from the built
binary with a generated web-only config (placeholder API key, scratch
`data_dir`, free port, password set through `microclaw web password`), signs
in, types into the composer, sends, reloads with history rendered, and types
again. It fails on any uncaught browser error or `console.error`, which is the
class of regression that shipped unnoticed in v0.8.0 through v0.10.0 (issue
#517: `Maximum update depth exceeded` on the first keystroke).

```sh
cargo build                                   # the test drives target/debug/microclaw
npm --prefix web/e2e ci                       # first time only
npm --prefix web/e2e run install-browser      # first time only: downloads Chromium
npm --prefix web run e2e                      # same as: npm --prefix web/e2e test
```

Point `MICROCLAW_BIN` at another binary to test a release build. In CI the
`Web UI Browser Smoke` job downloads the binary built by the ubuntu Rust job
and runs `scripts/ci/web_e2e.sh --no-build`; a failed run uploads the
Playwright report and traces as the `web-e2e-report` artifact.

## Troubleshooting

- Run `microclaw doctor` before changing configuration.
- Check `microclaw gateway status --json` for service state.
- Use `microclaw gateway logs 200` for recent service logs.
- If hooks return `503`, configure `channels.web.hooks_token` and restart.
- If a container cannot reach a host-side dependency, remember that `127.0.0.1` refers to the container itself.

The broader recovery and backup workflow is in the [operations runbook](runbook.md).
