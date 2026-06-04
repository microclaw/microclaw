# Eval fixtures

Sample session fixtures for `microclaw eval`. Each fixture is a recorded agent
session — either a bare JSON array of messages or an object with a `messages`
array (the shape persisted in the `sessions` table).

Fixtures in this directory are expected to **pass** and are the set the CI
"Trajectory eval gate" step runs. Negative examples live in `negative/` (a
subdirectory, so they are skipped by the non-recursive directory scan and never
break the gate).

```sh
# Check every passing fixture in this directory (CI gate; exits non-zero on failure)
microclaw eval docs/test/eval-fixtures

# Check a single fixture, emit a JSON report
microclaw eval docs/test/eval-fixtures/clean-session.json --json

# Fail the run if any tool produced an error
microclaw eval docs/test/eval-fixtures --strict-tool-errors

# Negative example — demonstrates a failing trajectory (exits non-zero)
microclaw eval docs/test/eval-fixtures/negative/dangling-tool-use.json
```

`microclaw eval` runs deterministic trajectory checks without calling any LLM:

- `no_dangling_tool_use` — every `tool_use` has a matching `tool_result`
- `no_orphan_tool_result` — every `tool_result` references a prior `tool_use`
- `ends_with_answer` — the session ends on a real assistant answer, not a raw `tool_result`
- `within_tool_budget` — tool-call count is within `--max-tool-calls`
- `no_tool_call_loop` — the same tool + arguments isn't repeated `--max-repeats` times (stuck loop)
- `no_error_streak` — no run of `--max-error-streak` consecutive tool errors
- `tool_errors` — surfaces tool errors (fails only under `--strict-tool-errors`)

`clean-session.json` passes all checks. Negative examples in `negative/`:
`dangling-tool-use.json` ends with a `tool_use` that never received a
`tool_result` (fails `no_dangling_tool_use`); `stuck-loop.json` repeats the same
`bash ls` call three times (fails `no_tool_call_loop`).
