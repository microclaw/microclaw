---
name: meeting-notes
description: "Turn raw meeting/call notes or a transcript into clean minutes: summary, decisions, and action items with owners and due dates. Use when users paste messy notes or a transcript and want it organized, or ask for minutes / a recap / action items. Triggers on mentions of meeting notes, minutes, recap, action items, takeaways, follow-ups, transcript, 会议纪要, 纪要, 行动项, 待办, 总结会议, 复盘."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "No external dependencies. Works on macOS, Linux, and Windows."
---

# Meeting Notes

Compress a messy meeting into something someone who missed it can act on in 30 seconds.

## Output structure

```
📌 Summary: <2–3 sentences: what the meeting was about and the outcome>

✅ Decisions:
  - <decision made, and any rationale>

📋 Action items:
  - [ ] <action> — owner: <name> — due: <date>

❓ Open questions / parking lot:
  - <unresolved item, who needs to follow up>
```

## How to extract

- **Decisions** = anything settled ("we'll go with X", "approved"). Record the choice, not the debate.
- **Action items** = a verb + an owner + (ideally) a due date. If owner/date is missing, mark it `owner: ?` so it's visibly unassigned rather than lost.
- **Open questions** = things raised but not resolved.
- Drop the chit-chat. Keep names attached to commitments.

## Guidance

- Lead with the summary and decisions; those are what people skim for.
- Don't invent owners or dates — flag the gap instead.
- Keep action items imperative and specific ("Send pricing draft to Sam", not "pricing").
- If a transcript is huge, summarize per agenda topic, then collate the action items at the end.
- Offer to schedule reminders for action items with due dates if the user wants.
