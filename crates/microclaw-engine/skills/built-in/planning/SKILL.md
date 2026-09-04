---
name: planning
description: "Turn a vague goal into a concrete, sequenced plan: break it into milestones and next actions, surface dependencies and risks, estimate effort, and propose a timeline. Use when users want to plan a project, trip, event, launch, study schedule, or any multi-step goal, or ask 'how should I approach X', 'help me plan', 'what's the roadmap'. Triggers on mentions of plan, roadmap, milestones, steps, schedule, organize, breakdown, 计划, 规划, 路线图, 步骤, 安排, 拆解."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "No external dependencies. Works on macOS, Linux, and Windows."
---

# Planning

Help the user go from "I want X" to "here's exactly what to do, in order." Keep it
tight and actionable — a plan they can start today, not a wall of theory.

## Method

1. **Clarify the goal & constraints** — what does "done" look like? Deadline, budget,
   who's involved? Ask at most one or two sharp questions only if truly blocking.
2. **Decompose** into 3–6 milestones (outcomes, not tasks). Each milestone = a checkpoint
   you could demo.
3. **Sequence & dependencies** — what must come before what. Flag the critical path.
4. **Next actions** — for the first milestone, list concrete next steps (verb-first,
   each doable in one sitting).
5. **Estimate & schedule** — rough effort per milestone; map to dates if a deadline exists.
6. **Risks & unknowns** — the 2–3 things most likely to derail it, plus a mitigation each.

## Output shape (adapt length to the ask)

```
🎯 Goal: <one line>
📍 Milestones:
  1. <outcome>  (~<effort>)  [depends on: —]
  2. <outcome>  (~<effort>)  [depends on: 1]
  ...
▶️ Start now:
  - [ ] <next action>
  - [ ] <next action>
⚠️ Watch out: <top risk → mitigation>
```

## Guidance

- Default to a short plan; expand only if the user asks for detail.
- Prefer the smallest plan that reaches the goal — cut nice-to-haves.
- If the goal is genuinely large, offer to spin the milestones into tracked tasks
  (e.g. scheduled tasks or sub-agents) so progress gets reported back.
- Re-plan cheaply: when reality changes, adjust the nearest milestone, not the whole thing.
