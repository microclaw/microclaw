# OWASP Agentic Top-10 Self-Assessment — 2026-08

Status: self-assessment, point-in-time · Date: 2026-08-07 · Owner: security
Scope: MicroClaw v0.3.5 + the v0.4.0 work in flight. Companion to
[`execution-model.md`](./execution-model.md) and [`secure-runtime.md`](./secure-runtime.md).

This maps MicroClaw's shipped controls onto the OWASP Agentic Security Initiative's ten
core agentic threats. Verdicts are deliberately conservative: **Mitigated** = layered
controls with tests; **Partial** = real controls, known gaps stated; **Accepted risk** =
documented posture, operator-owned. A self-assessment is not an audit; treat every
"Mitigated" as an invitation to falsify it.

| # | Threat | Verdict | Controls (authoritative locations) |
|---|---|---|---|
| T1 | Memory poisoning | **Partial** | Memory writes go through the `write_memory` tool (denied to subagents); per-chat memory isolation under `runtime/groups/<chat_id>/`; reflector changes are ordinary file diffs an operator can review. **Gap:** no provenance tagging on individual memory entries; a compromised main-loop turn can still write durable memory. Planned: none in v0.4.0 — tracked as a v0.5 candidate. |
| T2 | Tool misuse | **Mitigated** | `tool_policy` enforced at the single registry choke point; risk-tagged tools require explicit approval (`approval_required` flow); path guard blocks sensitive paths in file tools; sandboxed command execution with host/sandbox/dual policy; egress policy on configured endpoints and shared tool-input URLs. |
| T3 | Privilege compromise | **Mitigated** | Per-chat/per-channel/per-principal capability grants (main, scheduler, direct-channel, subagent principals); global blocks cannot be weakened by scoped grants; web auth with scoped API keys and rate limiting; sandbox credential filtering (no wholesale dotenv forwarding). |
| T4 | Resource overload | **Mitigated** | Per-chat daily token budgets (refusal with canned prefix); command timeouts; bounded tool iterations (`max_tool_iterations`); supervised loops with restart budgets; scheduler DLQ instead of unbounded retry; web request rate limiting. |
| T5 | Cascading hallucinations | **Partial** | Completion contracts with evidence-based verification across subagents, orchestration fan-in, scheduled tasks, and ACP; deep-research workflow runs an adversarial verifier and reports unsupported claims. **Gap:** contracts are opt-in per task; ordinary conversational turns carry no verification. |
| T6 | Intent breaking / goal manipulation | **Partial** | System-prompt soul/goal content is operator-owned files, not chat-writable; group messages only trigger on @mention; scheduled tasks run with operator-defined prompts and exit criteria. **Gap:** prompt injection via fetched web/tool content remains the industry's open problem; egress policy and output guardrail bound the blast radius rather than prevent the manipulation. |
| T7 | Misaligned / deceptive behavior | **Partial** | Output sanitizer strips private reasoning and fabricated tool traces before delivery (proof-pack scenario `output-sanitization`); post-output credential guardrail; contract verdicts distinguish claimed from verified completion. **Gap:** no systematic deception evals; Learning Foundry candidates require baseline-beating evaluation and manual promotion, which bounds but does not test for deceptive skill drift. |
| T8 | Repudiation / untraceability | **Mitigated** | Tamper-evident audit chain for tool, grant, egress, and recovery decisions; per-turn usage/insights accounting; recovery leaves explicit evidence of what resumed vs stopped; reliability scorecard published per release. |
| T9 | Identity spoofing / impersonation | **Partial** | Channel identity comes from platform-authenticated adapters; web sessions/API keys authenticated and scoped; A2A/ACP peers are explicitly configured. **Gap:** no named per-server trust tiers for MCP/A2A yet — shipping in v0.4.0 (WS-E3); until then all configured MCP servers carry equal ambient trust. |
| T10 | Overwhelming the human in the loop | **Partial** | High-risk approvals are blocking and fail closed (double-submit returns `approval_required` again, tested); heartbeat proactivity and all autonomous surfaces are off by default, so unsolicited agent-initiated volume is bounded. **Gap:** approvals are plain-text and per-event; no batching/rate-shaping of approval requests. v0.4.0 structured approvals (WS-C1) improve legibility; an aux-model reviewer (WS-C2, opt-in, advisory-only) reduces triage load without removing the human decision. |

## Reading the gaps honestly

Three themes recur in the Partial rows:

1. **Verification is opt-in.** Contracts verify what they are attached to; unattached turns
   are unverified. Extending default verification to more surfaces is the v0.5 question.
2. **Injection is bounded, not solved.** MicroClaw's posture is blast-radius control
   (egress, grants, sandbox, guardrails) plus auditability — not a claim of
   injection-proofing. Any vendor claiming the latter is selling something.
3. **Trust boundaries between agents are younger than trust boundaries around tools.**
   Principals and grants are mature; MCP/A2A tiering (E3) closes the loudest gap this
   cycle.

## Maintenance

Re-run this assessment at each minor release; update verdicts only with linked evidence
(test, audit event, or doc). The threat list follows the OWASP Agentic Security
Initiative's core taxonomy; if OWASP revises the list, revise the mapping rather than
freezing on this snapshot.
