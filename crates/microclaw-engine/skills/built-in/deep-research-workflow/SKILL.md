---
name: deep-research-workflow
description: "Run contract-governed deep research with parallel investigators, an adversarial verifier, and a cited synthesis. Use for high-stakes or broad research requests that need source independence, conflict detection, and explicit evidence quality. Triggers on deep research, comprehensive research, investigate thoroughly, 深度调研, 深入研究, 全面调查."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "Uses deep_research, subagents_orchestrate, and sessions_spawn. Works on macOS, Linux, and Windows."
---

# Contract-Governed Deep Research

Use this workflow when a normal `research` pass is not enough. The workflow has
four explicit stages and may only claim completion after the verifier contract
passes.

## 1. Frame and decompose

Write down:

- the decision or question;
- the time boundary and relevant geography or product scope;
- 3–6 non-overlapping sub-questions;
- claims that would materially change the answer;
- acceptable evidence and exclusions.

Do not delegate vague copies of the full question. Each work package must own a
distinct sub-question.

## 2. Gather in parallel

Call `subagents_orchestrate` with one `researcher` work package per sub-question.
Set `wait: true`. Every work package must:

1. use `deep_research` with multiple focused queries;
2. prefer primary, current sources;
3. return a claim ledger with claim, source URL, source date, authority, and
   whether the source is primary;
4. identify disagreement, missing evidence, and circular sourcing;
5. include these exit criteria:

```json
[
  {"type":"content_contains","text":"Sources"},
  {"type":"content_contains","text":"Caveats"}
]
```

Ask each investigator to cite stable URLs, not search-result pages. A failed
worker contract is evidence of incomplete research, not a reason to silently
drop that sub-question.

## 3. Verify adversarially

After fan-in, call `sessions_spawn` with specialist `researcher`, include the
complete investigator outputs as context, and ask it to disprove the draft
conclusions. The verifier must:

- map every material claim to at least one cited source;
- require two independent domains for claims marked high confidence, unless a
  single authoritative primary source is controlling;
- flag duplicated domains and sources that merely repeat the same origin;
- identify conflicts and select the controlling source using authority,
  directness, and recency;
- report unsupported claims and uncovered sub-questions;
- calculate:
  - citation coverage = supported material claims / material claims;
  - source independence = distinct controlling domains / controlling sources;
  - conflict disposition = resolved conflicts / detected conflicts;
- finish with `VERDICT: PASS` or `VERDICT: FAIL`.

Use this verifier exit contract:

```json
[
  {"type":"content_contains","text":"VERDICT:"},
  {"type":"content_contains","text":"citation coverage"},
  {"type":"content_contains","text":"unsupported claims"}
]
```

Do not synthesize a confident final answer after `VERDICT: FAIL`. Repair the
named gaps with one targeted gather-and-verify retry. If it still fails, return
the partial result and say exactly what remains unverified.

## 4. Synthesize

The final response must contain:

1. the bottom line;
2. findings organized around the original decision, not around worker names;
3. inline citations for every material factual claim;
4. explicit disagreement and uncertainty;
5. a compact evidence-quality footer:

```text
Evidence quality
- Citation coverage: <supported>/<material>
- Independent controlling domains: <count>
- Conflicts: <resolved>/<detected>
- Verifier: PASS|FAIL
```

Never present the number of search hits or agent agreement as corroboration.
Independence is measured at the controlling source/domain level.
