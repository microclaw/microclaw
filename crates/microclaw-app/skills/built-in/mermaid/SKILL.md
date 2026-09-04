---
name: mermaid
description: "Create diagrams as text using Mermaid syntax: flowcharts, sequence diagrams, gantt charts, ER diagrams, class diagrams, mindmaps, and state diagrams. Use when users want to visualize a process, architecture, timeline, data model, or flow, or ask for a diagram/chart/flowchart they can paste into Markdown/Notion/GitHub. Triggers on mentions of diagram, flowchart, sequence diagram, gantt, mindmap, ER diagram, visualize, 流程图, 时序图, 甘特图, 思维导图, 图表, 架构图."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "No external dependencies (text output). Works on macOS, Linux, and Windows."
---

# Mermaid Diagrams

Produce a Mermaid code block the user can paste into GitHub, GitLab, Notion, Obsidian, or
any Markdown that renders Mermaid. Pick the diagram type that fits the question.

## Flowchart (process / decision)

````
```mermaid
flowchart TD
    A[Start] --> B{Valid input?}
    B -- yes --> C[Process]
    B -- no  --> D[Return error]
    C --> E[Done]
```
````

## Sequence (who calls whom, over time)

````
```mermaid
sequenceDiagram
    User->>API: POST /order
    API->>DB: insert
    DB-->>API: ok
    API-->>User: 201 Created
```
````

## Gantt (timeline / plan)

````
```mermaid
gantt
    title Launch plan
    dateFormat YYYY-MM-DD
    section Build
    Design   :a1, 2026-06-01, 7d
    Develop  :after a1, 14d
```
````

## Also available

- `erDiagram` (data models), `classDiagram` (OOP structure), `stateDiagram-v2` (state machines),
  `mindmap` (idea trees), `pie` (proportions).

## Guidance

- Choose the type by intent: steps→flowchart, interactions→sequence, schedule→gantt, data→ER.
- Keep node labels short; quote labels containing spaces/punctuation: `A["Label: text"]`.
- Always return it inside a ` ```mermaid ` fenced block so it renders.
- Validate mentally that arrows/IDs are balanced; offer a PNG via a render tool only if asked.
