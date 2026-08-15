---
id: learning-foundry
title: Learning Foundry
sidebar_position: 18
---

Learning Foundry turns a user-selected direction into a recurring, governed
learning programme. It complements long-horizon learning:

- long-horizon learning distils evidence from work the agent already performed;
- Learning Foundry proactively researches an explicit capability gap during a
  bounded background epoch.

It does not fine-tune the model or let a research run rewrite live policy.

## Design

A learning track contains an objective, concrete directions, an allowlist of
source domains or source classes, a six-field cron schedule and IANA timezone,
per-epoch token and source-count budgets, and a promotion mode.

The runtime checks due tracks once per minute. Before an epoch starts it moves
the next-run timestamp forward, so duplicate scheduler ticks cannot run the
same epoch. The shared agent loop then performs a read-only research task. Its
prompt treats retrieved material as untrusted evidence and prohibits
credential use, external mutations, live-skill edits, and execution of
downloaded code.

A separate curator call may turn the report into one candidate. A valid
candidate must include a portable Agent Skills name, operational Markdown
instructions, dated source URLs, at least three self-contained validation
scenarios, and a risk classification. Candidate instructions pass the shared
prompt-injection scanner. Candidates remain inert; they are not included in
skill discovery or prompts.

## Isolated evaluation

Every new candidate enters an automatic paired evaluation before it can be
promoted. Each declared scenario is run twice against the same model:

1. the baseline arm receives only the scenario;
2. the candidate arm receives the same scenario plus the proposed skill.

These calls deliberately have no tool schema. They cannot access the network,
filesystem, credentials, shell, MCP, channel delivery, or live skills. A
separate conservative verifier applies the scenario's expected and forbidden
criteria to both responses. Candidate text and responses are passed as
untrusted data, not authority.

The database records paired pass/fail results, response excerpts, token counts,
durations, and regression count. The initial gate requires at least three
completed samples, zero baseline-pass/candidate-fail regressions, and strictly
more candidate passes than baseline passes. An infrastructure or verifier error
fails closed. Operators may rerun a failed evaluation, but cannot bypass it
during promotion.

This stage is an isolated behavioral simulation, not proof that a procedure can
successfully mutate a real external system. Tool-bearing workflows still need
the existing paired Shadow/Canary substrate before any future automatic
activation policy is enabled.

## Managing tracks

The `learning_tracks` tool supports `create`, `list`, `pause`, `resume`,
`archive`, and `run_now`.

```json
{
  "action": "create",
  "chat_id": 42,
  "name": "rust-runtime-reliability",
  "objective": "Learn repeatable ways to diagnose and recover Rust agent runtimes",
  "directions": ["Tokio task recovery", "SQLite crash consistency"],
  "allowed_sources": ["doc.rust-lang.org", "docs.rs", "github.com/tokio-rs"],
  "schedule": "0 0 3 * * *",
  "timezone": "America/Los_Angeles",
  "token_budget": 80000,
  "max_sources": 20,
  "promotion_mode": "propose"
}
```

Tracks, epochs, candidates, and evaluation summaries are returned by
`GET /api/learning_observability`. An administrator can promote a reviewed
new-skill candidate only after its isolated evaluation passes. A failed
candidate can be reevaluated with:

```http
POST /api/learning/tracks/candidates/evaluate
Content-Type: application/json

{"session_key":"main","candidate_id":"..."}
```

Promotion uses:

```http
POST /api/learning/tracks/candidates/promote
Content-Type: application/json

{"session_key":"main","candidate_id":"..."}
```

Promotion rejects a candidate whose name already belongs to a live skill.
Changes to an existing skill must use comparative reflection and paired shadow
evidence, preserving the active version as the baseline.

Promotion materializes the file but registers its lifecycle as `candidate`,
not `trusted`. Real task outcomes therefore act as the Canary stage through the
existing skill-governance policy: verified success can advance candidate →
trial → trusted, while repeated failures degrade it and restore a previous
trusted version when one exists. The isolated evaluator is a prerequisite for
this Canary; it does not replace outcome evidence.

## Safety and failure behavior

- Research and curation are separate model calls.
- No candidate is auto-activated.
- Source text is evidence, never authority.
- A candidate requires provenance and tests.
- Promotion fails closed unless paired isolated evaluation passed.
- Evaluation runs with no tools, network, filesystem, or credentials.
- Baseline/candidate regressions, token use, and latency are persisted.
- Injection scanning runs before storage and again before promotion.
- Only an admin-scoped API can promote a candidate.
- Existing skills cannot be overwritten through this path.
- Epoch failures and abstentions remain observable.
- Restarting does not lose tracks, epoch history, or candidates.

Learning Foundry optimizes reusable task behavior only. Tool guardrails,
filesystem/network policies, hooks, and channel authorization remain
authoritative.
