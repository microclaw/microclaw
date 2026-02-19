# RFC 0002: Hooks Platform MVP

- Status: Draft
- Owner: agent runtime/tools
- Target Phase: Phase 2
- Last Updated: 2026-02-19

## Context

MicroClaw has risk-gating in tool runtime but lacks a general lifecycle hook system for policy injection, auditing, and extension.

## Goals

- Introduce a hooks runtime with three initial events:
  - `BeforeLLMCall`
  - `BeforeToolCall`
  - `AfterToolCall`
- Support hook outcomes:
  - `allow`
  - `block`
  - `modify` (structured, limited fields)
- Add discovery and CLI controls.

## Non-Goals

- Arbitrary mutation of full message history in v1.
- UI hook editor in this phase.

## Proposed Design

### Hook Package Layout

```
<root>/hooks/<hook-name>/
  HOOK.md
  handler.(sh|js|ts)
```

### HOOK.md Metadata

Frontmatter fields:

- `name`
- `description`
- `events`
- `command`
- `timeout`
- `requires` (os/bins/env)

### Event Payloads

- `BeforeLLMCall`
  - provider, model, iteration, tool_count, serialized messages
- `BeforeToolCall`
  - tool name, arguments, session key, channel metadata
- `AfterToolCall`
  - tool name, arguments, result/error summary

### Hook Result Contract

- exit 0 + no stdout => allow
- exit 1 + stderr => block(reason)
- exit 0 + stdout JSON => modify (validated schema)

`modify` constraints v1:

- `BeforeLLMCall`: can append guardrail hint and redact known keys
- `BeforeToolCall`: can rewrite only allowlisted argument keys
- `AfterToolCall`: can redact response fields only

### Execution Model

- mutating events: sequential
- read-only events (`AfterToolCall`): parallel eligible in future, sequential in v1 for simplicity

### CLI

- `microclaw hooks list`
- `microclaw hooks info <name>`
- `microclaw hooks enable <name>`
- `microclaw hooks disable <name>`

## Security Considerations

- Hook command execution timeout hard cap.
- Hook stderr/stdout size cap.
- Ignore ineligible hooks; do not fail runtime.
- No network sandbox bypass introduced by default.

## Migration Plan

- Feature-flagged startup: `hooks.enabled`.
- No-op when directory absent.

## Testing Plan

- Parsing `HOOK.md` frontmatter
- Eligibility checks
- Block/modify semantics
- Agent loop integration tests across 3 events

## Rollback Plan

- Set `hooks.enabled = false`.
- Keep hook files on disk; runtime skips loading.
