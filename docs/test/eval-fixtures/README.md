# Eval fixtures

Sample session fixtures for `microclaw eval`. Each fixture is a recorded agent
session — either a bare JSON array of messages or an object with a `messages`
array (the shape persisted in the `sessions` table).

```sh
# Check every fixture in this directory (CI gate; exits non-zero on failure)
microclaw eval docs/test/eval-fixtures

# Check a single fixture, emit a JSON report
microclaw eval docs/test/eval-fixtures/clean-session.json --json

# Fail the run if any tool produced an error
microclaw eval docs/test/eval-fixtures --strict-tool-errors
```

`microclaw eval` runs deterministic trajectory checks without calling any LLM:

- `no_dangling_tool_use` — every `tool_use` has a matching `tool_result`
- `no_orphan_tool_result` — every `tool_result` references a prior `tool_use`
- `ends_with_answer` — the session ends on a real assistant answer, not a raw `tool_result`
- `within_tool_budget` — tool-call count is within `--max-tool-calls`
- `tool_errors` — surfaces tool errors (fails only under `--strict-tool-errors`)

`clean-session.json` passes all checks; `dangling-tool-use.json` is the negative
example — it ends with a `tool_use` that never received a `tool_result`, so it
fails `no_dangling_tool_use`.
