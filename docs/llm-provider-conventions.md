# LLM Provider Conventions

This project keeps `src/llm.rs` model-agnostic.

## Rules

- Do not branch on specific model name strings in provider send/translation paths.
- Represent provider-specific behavior as capability flags and branch on capabilities.
- Keep provider/model presets in setup/config surfaces; keep `llm.rs` focused on protocol translation and runtime behavior.
- Write tests around capability combinations rather than model-name cases.
- For OpenAI-compatible tool calling, treat wire-format variance as protocol compatibility work:
  - Accept `tool_calls[*].index` as optional in streaming deltas; when absent, fall back to array position.
  - Accept `tool_calls[*].function.arguments` as either JSON string or JSON object/value.
  - Do not keep `stop_reason=tool_use` unless at least one parsed `ToolUse` block exists.
- Keep runtime diagnostics explicit:
  - `agent_engine` iteration logs should include `tool_calls` when `stop_reason="tool_use"`.
  - If `stop_reason="tool_use"` but no tool calls are parsed, log a warning and end the turn safely.

## Why

- Reduces model-churn edits in core runtime code.
- Makes behavior portable across providers exposing similar capabilities.
- Keeps compatibility logic explicit, testable, and easier to maintain.
