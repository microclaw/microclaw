# Completion Contracts

Status: **shipped (phase 1)** · Origin: v0.4.0 item C+E in
[`roadmap/competitive-intel-update-2026-07.md`](./roadmap/competitive-intel-update-2026-07.md)

A completion contract makes "task done" mean **verified done**: instead of
trusting a sub-agent's self-report, the runtime executes a small list of
machine-checkable exit criteria when the run finishes and stamps the result
`VERIFIED` or `FAILED` with per-criterion evidence.

## Usage

Pass `exit_criteria` when spawning a sub-agent:

```json
{
  "task": "Add the copyright header to every file under src/",
  "exit_criteria": [
    {"type": "command", "run": "grep -rL 'Copyright' src --include='*.rs' | wc -l", "expect_contains": "0"},
    {"type": "file_exists", "path": "report.md"},
    {"type": "result_contains", "needle": "files updated"}
  ]
}
```

The sub-agent sees the contract in its task prompt (it knows exactly what
will be checked), and when it finishes the runtime prepends a report to the
result:

```
[completion contract] FAILED — 2/3 criteria passed. Do NOT treat this task as
done; the failed criteria below are the remaining work.
✓ command `grep -rL ...` succeeds and prints "0" — 0
✓ file `report.md` exists — .../report.md exists
✗ result text contains "files updated" — "files updated" missing from result
```

The parent agent loop sees the same report, so it can re-spawn with the
failed criteria as the new task instead of relaying a false "done" to the
user. The verdict is also written to the run's event log
(`contract verified|failed n/m`).

## Criterion types

| type | fields | passes when |
|---|---|---|
| `file_exists` | `path` | file exists |
| `file_contains` | `path`, `needle` | file readable and contains substring |
| `file_min_bytes` | `path`, `min_bytes` | file size ≥ `min_bytes` |
| `result_contains` | `needle` | final result text contains substring |
| `command` | `run`, `expect_contains?` | command exits 0 (and output contains `expect_contains` when set) |

Max 8 criteria per contract.

## Safety model

- **File paths are jailed**: only relative paths, no `..`, no `~`; resolved
  inside the chat's working directory (`working_dir_isolation` respected).
  A contract cannot probe host paths, and evidence excerpts are capped at
  300 chars.
- **Commands run through the sub-agent's own `bash` tool** via the registry
  choke point — the sandbox router, dangerous-pattern checks, and
  `tool_policy` all apply exactly as if the agent had run the command itself.
- **Fail closed**: unreadable files, runner errors, and malformed criteria
  are failures (malformed contracts are rejected at spawn time with a
  descriptive error).
- The ACP runtime does not support contracts yet; spawning with
  `exit_criteria` on `runtime: acp` is rejected.

## Phase 2 (shipped)

- **Bounded in-run auto-retry**: when a run's contract fails, the sub-agent
  gets exactly one chance to finish the unmet criteria (the failure report is
  fed back into its conversation; `contract_retry` event logged) before the
  FAILED result is returned.
- **Orchestrate work-package contracts**: `subagents_orchestrate`
  `work_packages` entries may be objects `{task, exit_criteria?}`. With
  `wait: true`, a completed worker whose result carries the FAILED marker is
  re-spawned once with the failure evidence as context (contract-aware
  fan-in retry, reported in the `retried` field), and the replacement's
  artifacts are merged instead.
- **Scheduled-task contracts**: `schedule_task` accepts `exit_criteria`
  (stored with the task). After each run the contract is verified; the
  annotated report is delivered to the chat and a failed contract records the
  run as failed — one-shot tasks then flow into the existing DLQ +
  auto-replay, which bounds retries via `dlq_max_replay_attempts`.

## Still deferred

- ACP-runtime contracts (the ACP result path bypasses the verifier; spawns
  with contracts on `runtime: acp` are rejected).
