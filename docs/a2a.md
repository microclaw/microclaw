# MicroClaw A2A

MicroClaw now supports a lightweight agent-to-agent HTTP flow for instance-to-instance delegation.

## What it provides

- A discoverable agent card at `/.well-known/agent.json` and `/api/a2a/agent-card`
- An authenticated inbound message endpoint at `/api/a2a/message`
- Two built-in tools:
  - `a2a_list_peers`
  - `a2a_send`

## Configuration

Add an `a2a` section to `microclaw.config.yaml`:

```yaml
a2a:
  enabled: true
  public_base_url: https://planner.example.com
  agent_name: Planner
  agent_description: Routes work to specialized agents
  shared_tokens:
    - shared-a2a-token
  peers:
    worker:
      base_url: https://worker.example.com
      bearer_token: shared-a2a-token
      description: Executes implementation tasks
      default_session_key: a2a:worker
```

## Usage

From a local session, the agent can inspect peers:

```text
Use a2a_list_peers and tell me which remote agents are available.
```

Or delegate work:

```text
Use a2a_send to ask peer `worker` to summarize the current repository layout.
```

## Request shape

`POST /api/a2a/message` accepts:

```json
{
  "sessionKey": "a2a:worker",
  "sourceAgent": "Planner",
  "sourceUrl": "https://planner.example.com",
  "message": "Review the current repo and summarize the main modules."
}
```

The endpoint returns:

```json
{
  "ok": true,
  "protocol_version": "microclaw-a2a/v1",
  "agent_name": "Worker",
  "session_key": "a2a:worker",
  "response": "..."
}
```

## Follow-up UX work

The current A2A config flow is ready to use and merge, but the next iteration should improve operator ergonomics in the Web settings UI:

- Add finer validation and clearer inline errors for A2A config fields.
  - Examples: invalid peer names, missing/invalid `base_url`, duplicate peer names, malformed token lists.
- Add a peer connectivity test flow from the Web UI.
  - Goal: let operators verify agent-card discovery and message endpoint reachability before saving or delegating work.
- Add a "duplicate peer" action in the Web UI.
  - Goal: make it faster to create similar peer entries when only host/token/session defaults differ.

Suggested priority:

1. Better validation
2. Connectivity test
3. Duplicate peer action
