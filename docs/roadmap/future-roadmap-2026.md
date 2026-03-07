# Future Roadmap (2026)

Last Updated: 2026-03-07

## Sub-agent evolution

- Current baseline:
  - `sub_agent` tool is available for bounded delegation.
  - Sub-agents stay constrained (no recursive sub-agent calls and no side-effect messaging tools).
- Next target:
  - stronger parent/child task contract (clear required fields and result schema)
  - timeout/cancel controls for long-running delegated work
  - better recovery on malformed tool calls so the parent loop can self-correct cleanly
- Later target:
  - multi-sub-agent orchestration for fan-out/fan-in workflows
  - explicit orchestration observability (per-child latency, failure type, retries)

## Runtime priorities adjacent to sub-agents

- Continue stability hardening for tool execution reliability.
- Keep memory quality and context compaction predictable under longer sessions.
- Improve web/API observability for request lifecycle and failure diagnostics.
