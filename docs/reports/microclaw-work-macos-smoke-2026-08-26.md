# MicroClaw Work macOS smoke report — 2026-08-26

Status: **passed with open accessibility acceptance work**

This report records a live test of the optimized, bundled macOS application at
`target/microclaw-work-app/work-release/MicroClaw Work.app`. It used the local
Codex account detected by Work and the model selected by the installed Codex
client. No repository files were connected to the conversation or modified by
the task; project-tool checks used a disposable fixture under `/private/tmp`.

## Environment

- Product: MicroClaw Work `0.1.0`
- Platform: macOS
- Provider: `openai-codex`
- Model: `gpt-5.6-sol`
- Runtime path: shared MicroClaw Agent Engine through
  `microclaw-work-runtime`
- Workspaces: private Work Home and a disposable selected project fixture

## Evidence

1. The packaged application launched into the conversation-first home and
   restored the existing Chinese composer draft.
2. Submitting `请分析这个项目，并给出下一步计划。` created one durable user
   message and entered the active-run composer state.
3. **Stop** interrupted the live provider run and produced a visible
   **Cancelled** state with **Retry** available.
4. **Retry** reused the same conversation and Agent Engine session. It did not
   insert a duplicate user message.
5. The retried task completed with a visible, nonempty Codex response after
   approximately 21 seconds.
6. Command-Q terminated the process. Relaunch restored the same single user
   message, assistant response, conversation title, and completed state.
7. The rebuilt DMG passed `hdiutil verify`. Its SHA-256 is
   `ddcb5a00ee7e67609821ddbe273e946f63fa8ee383990425011cdebcba1bfa58`.
8. A selected project fixture containing `README.md` and `TASK.md` was opened
   in a fresh conversation. Codex published a three-step plan, read `TASK.md`
   with the native file tool, created `RESULT.md`, re-read the result, and
   returned a visible completion.
9. Work created a pre-task shadow-git checkpoint, projected the new file as a
   bounded nine-line unified diff, and entered pending review. No `chat/` or
   `shared/` runtime directory was created inside the project.
10. The Details inspector remained fully inside the compact application window
    with a long conversation title. Accept and Revert appeared before the diff.
11. Revert displayed a native destructive-action confirmation. Confirming it
    removed `RESULT.md`, retained the two original files byte-for-byte, stored
    review status `reverted`, and recorded the checkpoint restoration event.
12. A fresh conversation requested the high-risk `bash` tool for the read-only
    command `pwd`. Work paused on an inline card with **Approve once**,
    **Always allow 'bash' in this chat**, and **Deny**. Choosing **Approve once**
    resumed the same persisted conversation, executed the command successfully,
    and produced a visible final response without storing a standing grant.
    The durable event log pairs the initial `approval_required` tool result with
    the approval response and the successful resumed tool call.

This exercise also confirms the provider-level SSE normalization added for
Codex responses: streamed output remains visible when the terminal response
event does not repeat the accumulated text.

## Open acceptance work

- AccessKit exposes the primary controls and the composer. A later visual pass
  confirmed that Tab moves from the composer to **Try Demo**, skips the disabled
  **Stop** action, and then focuses **Send**; Shift-Tab reverses the path. The
  accessibility snapshot did not expose the focused attribute, so the visible
  native focus ring is the authoritative evidence for this check. VoiceOver
  still requires a direct manual speech pass. A later Accessibility-tree audit
  found and fixed unnamed conversation buttons; conversation rows now expose
  their durable titles, and the regression check is reproducible with
  `scripts/audit_work_macos_accessibility.sh`.
- Unicode Chinese text, Return-to-send, and Shift-Return multiline input are
  verified. A later isolated run set `MICROCLAW_WORK_DATA_DIR` to a disposable
  `/private/tmp` directory, selected an enabled macOS Pinyin input source, and
  physically entered `nihao`. GPUI displayed marked text, accepted the numbered
  Chinese candidate `你哈哦`, persisted it as `composer_draft`, and restored the
  same value after process termination and relaunch. The normal Work data
  directory was not opened; the input source was restored to U.S. and the
  disposable directory was removed after verification.
- A signed build exists, but a live Apple notarization and stapling run still
  requires the release keychain profile.
- Longer multi-tool tasks and multi-day survival remain separate acceptance
  runs.
