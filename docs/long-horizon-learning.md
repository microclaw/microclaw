# Long-horizon learning

MicroClaw's first long-horizon learning layer turns completed work into
traceable evidence and uses that evidence to govern reusable skills. It does
not let the model silently rewrite its own policy or treat fluent output as
proof of success.

## Data model

- `goal_states` stores the active objective, constraints, progress, and budget.
- `experience_runs` records one interactive, recovery, or scheduled execution
  with its environment fingerprint, status, summary, duration, token counts,
  model-request count, tool calls/errors, estimated cost, and a versioned task
  signature.
- `outcome_envelopes` is the versioned, replayable ingestion log shared by
  runtime completion, tool-result summaries, scheduler/environment failures,
  completion contracts, rules, models, and human reviewers. Normalized
  verifier and feedback rows are projections of these envelopes.
- `experience_feedback` stores caller-attributed, idempotent human corrections.
- `experience_retrieval_logs` records exactly which prior runs were injected
  into a new run, their rank, relevance score, and the selection reason.
- `verifier_results` stores independent verdicts and evidence. Deterministic
  checks outrank environmental, human, rule-based, model-based, and runtime
  completion signals.
- `skill_versions` stores immutable skill content and its hash.
- `skill_activation_logs` attributes a skill version to an experience run.
- `skill_outcomes` projects the best verifier result for each activated skill
  and run.
- `skill_lifecycle` and `skill_lifecycle_events` store current governance state
  and an auditable transition history.

The runtime records a low-confidence completion signal for every turn.
Scheduled completion contracts provide deterministic evidence and therefore
supersede that signal. Operators can add scoped human evidence through the Web
API. Runtime and model-based self-evaluation remain observable, but only
deterministic, environmental, human, or rule-based evidence can change a skill
lifecycle or establish an environment-specific contraindication.

Multiple active human feedback items are aggregated by confidence instead of
overwriting each other. Feedback supports a caller-scoped idempotency id and an
optional RFC3339 expiry. Expired evidence is excluded from current quality and
applicability calculations.

Experience ids are UUIDs rather than process-local counters. Scheduler timeout
keeps the agent future alive long enough to run its cancellation epilogue, then
records environmental timeout evidence. On startup, runs left active by a
previous process are retired as interrupted; that restart evidence is
observable but does not govern skills.

## Skill lifecycle

Agent-created versions begin as `candidate`.

| Transition | Current policy |
| --- | --- |
| candidate -> trial | first verified passing outcome |
| candidate -> degraded | two verified failing outcomes |
| trial -> trusted | at least three outcomes, at least 80% pass rate, and Wilson utility lower bound at least 40% (`z=1.96`) |
| trial -> degraded | at least three outcomes and below 50% pass rate |
| trusted -> degraded | at least five outcomes and below 60% pass rate |
| any active state -> archived | operator deletion or inactive-skill archive |
| degraded -> trusted | explicit rollback to a recorded version |

Candidate and trial skills remain visibly marked as experimental when loaded.
Degraded and archived skills cannot be activated.

When a run activates more than one skill, its outcome is retained with
fractional attribution for audit but cannot automatically govern any of those
skills. This avoids assigning the full success or failure of a combined
workflow to every participant.

Applicability is learned conservatively from verified outcomes. If the active
version has at least two outcomes in the exact current environment fingerprint
and fewer than half passed, activation is blocked as a learned
contraindication. A new version starts with fresh outcome attribution.

## Interfaces

- The Web settings **Learning** panel lists recent runs and renders the prior
  experiences used, their selection reasons, activated skills, metrics, and
  outcome evidence for the selected run.
- `/usage` includes aggregate experience and governed-skill health.
- `/learning [run_id]` shows one run's objective/result, prior experiences
  injected into it, activated skills, and complete outcome evidence. With no
  id it displays the latest run in the current chat.
- `GET /api/learning_observability?session_key=...` returns the active goal,
  aggregate run counts, recent runs, and skill lifecycle summaries.
- `POST /api/learning/feedback` accepts `session_key`, `run_id`, `verdict`,
  optional `evidence`, `confidence`, `scope`, `feedback_id`, and `valid_until`.
  The run must belong to the selected chat.
- `GET /api/learning/experiences` searches strongly verified experience within
  the selected chat by objective/result relevance and optional environment.
- `GET /api/learning/experiences/:run_id?session_key=...` returns the complete
  run detail, including versioned outcome envelopes, normalized feedback,
  activated skills, and retrieved-experience audit records.
- `GET /api/learning/policy` exposes the current thresholds.
- `PUT /api/learning/policy` is admin-scoped and updates validated promotion
  and degradation thresholds with an audit event.
- `skill_manage` registers new versions and supports `rollback` with an optional
  `target_version`.

## Safety boundary

This layer optimizes reusable task behavior, not authorization policy. Tool
guardrails, hooks, filesystem/network restrictions, and channel authorization
remain authoritative. Verifier evidence is retained so promotion, degradation,
and rollback decisions can be inspected instead of being inferred from the
model's narrative.

Verified experience retrieval is chat-scoped. Historical objectives and
summaries must pass the shared injection scanner before prompt inclusion, and
the prompt labels every recalled record as untrusted observation rather than
instruction.

Memory erasure includes chat-scoped goals and experience evidence. After that
evidence is removed, affected skill lifecycles are recomputed from their source
baseline and the remaining valid, unambiguous evidence; derived trust therefore
cannot survive deletion of all supporting data.

## Task signatures and risk-adjusted utility

Task Signature v1 deterministically assigns every run:

- a broad `task_type`, such as `software_development`, `operations`, or
  `information_retrieval`;
- a narrower `task_family`, such as `debugging`, `deployment`, or `research`;
- sorted capability tags such as `coding`, `verification`, `browser`, or
  `data`;
- a stable SHA-256 signature hash over the canonical classification.

The classifier supports common English and Chinese task language. Schema v38
backfills existing runs, so historical outcomes participate in the same
stratified statistics.

Skill quality is reported both overall and by
`skill × version × task_type × task_family`. Alongside raw pass rate, MicroClaw
computes the Wilson score lower bound using the governance policy's confidence
`z` value (default `1.96`). Trial promotion requires the minimum sample count,
the raw pass-rate threshold, and the utility lower-bound threshold. This keeps
a tiny perfect sample from being treated as established quality.

Verified-experience retrieval combines lexical relevance, exact environment
match, task type/family compatibility, capability overlap, and the
risk-adjusted utility lower bound. Applicability contraindications are scoped
to the current task family and environment rather than treating a skill as
universally bad after a context-specific failure.
