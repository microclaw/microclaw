# MicroClaw Work Phase 1 application-boundary report

Status: **In progress — real Agent Engine adapter landed** · Date: **2026-08-25**

This report records the first Phase 1 increment from the active
[`MicroClaw Work proposal`](../roadmap/microclaw-work-proposal-cn.md).

## Change

The framework-independent Work model moved out of the GPUI package into a new
workspace crate:

```text
apps/microclaw-work
  GPUI views, input, timers, platform data path, native packaging
        | commands/projection             | foreground execution
        v                                 v
crates/microclaw-work-app        crates/microclaw-work-runtime
  lifecycle, approval,             start, events, cancellation,
  snapshot, persistence             worker lifecycle
        ^                                 |
        | RuntimeEventEnvelope            v
        +------------------------ microclaw::HeadlessRuntime
                          shared provider-neutral Agent Engine
```

The desktop crate no longer defines a library or owns Work lifecycle policy.
It renders `microclaw-work-app` projections and translates UI actions into
domain commands. Timed synthetic events remain in the desktop spike only until
the production runtime event source replaces them.

The application crate now exposes one explicit lifecycle reducer:

```text
WorkCommand -> WorkSessionSnapshot::apply -> CommandOutcome | WorkCommandError
```

Start, progress, approval request, approval, and reset all use this path.
Invalid state transitions are rejected in the application layer rather than
being interpreted independently by GPUI listeners.

## Shared runtime event boundary

The Server's existing `AgentEvent` definition now lives in
`microclaw-core::runtime_event::RuntimeEvent`. The root Agent Engine re-exports
that type as `AgentEvent`, so all existing Server event producers and channel
consumers continue to compile while Work consumes the exact same enum.

Transport and replay use `RuntimeEventEnvelope`, which carries:

- a protocol schema version;
- a stable runtime run ID;
- a monotonically increasing sequence;
- the provider-neutral runtime event.

The Work reducer accepts the envelope through
`WorkCommand::ApplyRuntimeEvent`. Starting with protocol v2, the runtime tool call ID
so tool starts and results pair deterministically even when execution is
parallel. It projects structured tool activity, approval, file
diffs, subagents, cancellation, and completion into UI-independent Work state.
Sequence gaps and unsupported protocol versions are rejected before the
projection is mutated.

`apps/microclaw-work-headless` is a no-GPUI harness. It can run a deterministic
event stream or replay JSONL envelopes from standard input and emits the final
Work session as JSON. It proves that GPUI is one projection consumer, not the
owner of the task loop.

The root runtime now also exposes `HeadlessRuntime`, a reusable application
service extracted from the existing `microclaw run` path. It owns `AppState`,
session persistence, the existing `process_with_agent_with_events` call, and
the raw-event-to-envelope bridge. It starts no Server channels, Web server,
scheduler, or gateway. The original CLI now delegates to this service.

The harness has a `real` mode which:

1. loads the normal MicroClaw provider configuration;
2. uses the current directory as the Work workspace;
3. starts the existing provider-neutral Agent Engine;
4. projects every real envelope through `microclaw-work-app`;
5. returns the completed Work session as JSON.

An offline integration test replaces only the LLM provider with a deterministic
fake. The database, session lifecycle, Agent Engine, event emission, envelope
sequencing, and Work-facing application service remain real. This verifies the
boundary without API credentials, network access, or model cost.

## Dependency evidence

`cargo tree -p microclaw-work-app --depth 1 --locked` contains only:

- `microclaw-core` for the shared runtime event protocol;
- `serde`;
- `serde_json`;
- `tempfile` as a development dependency.

It contains no GPUI, platform, channel, provider, or Server dependency.

## Verification

```text
cargo test -p microclaw-core --locked                            51 passed
cargo test -p microclaw-work-app --locked                        24 passed
cargo test -p microclaw-work-runtime --locked                     6 passed
cargo test -p microclaw-work --locked                             0 tests; build passed
cargo test -p microclaw-work-headless --locked                    2 passed
cargo clippy -p microclaw-work-app --all-targets -- -D warnings passed
cargo clippy -p microclaw-work-headless --all-targets --no-deps  passed
cargo check -p microclaw-work --locked                           passed
cargo clippy -p microclaw-work --all-targets --no-deps          passed
cargo check -p microclaw --lib --locked                          passed
cargo test -p microclaw event_tap --lib --locked                 12 passed
cargo test -p microclaw agent_engine::tests --lib --locked       43 passed
cargo test -p microclaw headless::tests --lib --locked            3 passed
cargo run -p microclaw-work-headless -- demo ...                 completed
microclaw config check                                           passed
```

A live, no-tool smoke request reached the configured external provider, but
the provider rejected the repository's configured `gpt-5.3-codex` model for
ChatGPT Account authentication with HTTP 400. This is configuration evidence,
not a completed live-run result; the report does not count it as a passing
end-to-end task. No private workspace file was sent during that request.

## Next boundary work

- Add an application-service port for starting, approving, cancelling, and
  resuming a runtime run rather than only projecting its events.
- Add event persistence/replay at the Server boundary and coalesce high-rate
  text deltas before they enter the durable Work timeline.

The existing provider-neutral Agent Engine must not be copied into this crate.

## Desktop runtime connection

The GPUI desktop now links the same `HeadlessRuntime` service used by the CLI
and headless harness. A named operating-system thread owns a Tokio runtime and
forwards only `RuntimeMessage` values to GPUI:

```text
GPUI task input
  -> desktop runtime worker
  -> HeadlessRuntime
  -> existing Agent Engine
  -> RuntimeEventEnvelope
  -> WorkCommand::ApplyRuntimeEvent
  -> GPUI projection + atomic snapshot persistence
```

No model call or tool execution runs on the GPUI thread. The desktop keeps an
explicit Demo action for credential-free UI testing; the primary action runs
the production Agent Loop. Configuration/provider errors become a terminal
`Failed` Work status.

Approval is a multi-turn lifecycle. A `FinalResponse` that follows
`ApprovalRequired` no longer clears the approval state. The desktop's approve
action applies the local transition and submits approve-once (`1`) into the
same persisted runtime session, allowing the existing Agent Engine to resume
without a separate desktop-only approval implementation.

The foreground worker is no longer a private module inside the GPUI binary.
`microclaw-work-runtime::WorkRuntimeService` now owns task start, the dedicated
Tokio worker, event subscription, terminal results, and cancellation. Its
public request/handle/message boundary has no GPUI types. The desktop therefore
contains no Tokio dependency and cannot silently grow a second runtime-control
implementation. Future headless projections and Work-to-Server transports can
adapt the same application-service boundary.

## Native model onboarding

The desktop no longer requires a terminal-only `microclaw setup` detour for
its first task. An English Model Settings surface edits the provider, model,
optional base URL, and a masked password-semantic API-key input. Existing keys
are represented only by a boolean “saved” state and are never copied back into
the GPUI field or accessibility tree; leaving the field blank preserves the
saved value.

`WorkRuntimeService` owns one explicit config path. Resolution prefers
`MICROCLAW_WORK_CONFIG`, then a discoverable shared Server config, then Work's
platform-local data directory. The new shared
`Config::load_from_path_for_headless` retains provider, security, path, and tool
validation while waiving only the irrelevant Server delivery-channel
requirement. New Work configs are atomically renamed and mode `0600` on Unix;
model-only updates use comment-preserving shared persistence. Five focused
runtime-service tests cover creation, reload, comment/key preservation,
credential validation, URL validation, cancellation, and run-ID uniqueness.

Computer Use then exercised the first-run flow against an isolated `/tmp`
configuration. It verified the English settings layout, an accessibility role
of `secure text field` with no exposed value, masked on-screen key rendering,
the missing-key validation message, keyless Ollama creation, immediate sidebar
readiness, mode `0600`, preservation of a saved key after a blank edit, and
provider/model restoration after a full native process restart. The isolated
run did not read or modify the user's production model configuration.

## Post-task review and recovery

Runtime Event protocol v3 adds `CheckpointCreated`. Work forces the existing
shadow-git checkpoint mechanism on for foreground runs and durably records only
the first checkpoint of a task as its baseline; approval-continuation turns
cannot replace it. Session schema v7 adds the baseline, an explicit Pending /
Accepted / Reverted review state, and a stable title so a same-session follow-up
composer does not erase the recent-task label.

A completed task with both a baseline and file diffs now requires an explicit
review decision. Accept is a durable projection command. Continue clears the
composer, preserves the title, and uses the same runtime session on the next
run. Revert presents a native critical confirmation and calls a background
runtime port rather than running Git on the GPUI thread.

The shared restore implementation now uses `git read-tree --reset -u` plus a
single-force clean. This fixes two correctness gaps in the previous `/rewind`:
empty baselines are restorable, and files tracked only by a later checkpoint
are removed. New non-ignored files are also removed, while standard excludes
such as `.env` and nested repositories remain protected. Five checkpoint tests
cover empty and populated baselines, later tracked files, new untracked files,
ignored secrets, listing, and hash injection guards; the runtime-service test
proves the UI port restores modified files and removes created files.

Computer Use visually verified the English Review panel at 1180×760, including
the pre-task checkpoint timeline event and non-overflowing vertical Accept,
Revert, and Continue controls. The macOS accessibility cache stopped exposing
semantic controls after the direct test-process restart, so button transition
claims come from the focused projection/runtime tests rather than an unreliable
semantic click; no passing native-click claim is made for that portion.

## Agent-owned live plans

Runtime Event protocol v4 adds `PlanUpdated`, a provider-neutral list of titled
steps with Pending, In Progress, or Completed status. The shared tool executor
publishes this event only after `todo_write` succeeds, using the effective input
that passed policy hooks. Failed writes never update a client projection. Web
also forwards the same structured event, so the protocol is not desktop-only.

Work session schema v8 removes the fixed four-step placeholder plan. A new task
starts with no plan and the native UI says it is waiting for the Agent. Each
subsequent full plan replaces the prior projection, is bounded to 100 steps,
and persists with the session. Older v5-v7 snapshots discard their synthetic
plan during migration rather than presenting it as Agent-authored state. The
demo exercises the same `PlanUpdated` projection path with explicit completed,
active, and pending statuses.

After rebuilding and ad-hoc signing the macOS bundle, Computer Use launched the
unlocked native app and activated Demo by screen coordinate because GPUI still
did not expose semantic controls. The resulting 1180×760 view visibly showed
one completed step (`✓`), one active step (`●`), and two pending steps (`○`),
alongside the matching plan-update timeline and approval state. This is a
passing native visual/click claim for the live-plan surface.

## In-run steering

The foreground loop is now user-steerable without starting another run. While
a task is active, the native task composer becomes an English guidance field
with a `Send Update` action. `WorkRunSteering` carries the update to the
background runtime worker, which calls `HeadlessRuntime::steer_session` for the
same durable session. That method uses the existing `ChatTurnQueue`; the shared
Agent Engine absorbs the message at its established tool-completion or
end-turn breakpoint and emits the existing `MidTurnInjection` event.

The desktop records guidance in its durable timeline only after the active
runtime reports that the queue accepted it. Empty updates, idle sessions, and
runs that finish during the send race are rejected rather than displayed as
accepted. The Demo uses the same Work application command so the native state
can be exercised without a provider credential.

A root integration test runs the real Agent Engine with a deterministic model:
the first model call requests a real built-in tool, Work queues guidance while
that call is active, and the second model call proves the guidance is present
in the provider-neutral message context. Focused runtime tests separately cover
control-channel validation, and the Work application test proves accepted
guidance survives snapshot reload.

The updated macOS bundle builds, lints its property list, signs, and passes
strict signature verification. The restored GPUI window launched successfully,
but its semantic controls were again absent from the accessibility snapshot and
coordinate clicks stopped dispatching reliably in the existing Approval state.
Accordingly, this increment claims native build/render coverage and the real
Agent Engine integration test above, but does not claim a passing automated
native `Send Update` click.

## Structured approval cards

Runtime Event protocol v5 replaces ambiguous approval label strings with
`RuntimeApprovalOption { value, label, decision, kind }`. `value` is the stable response
sent back to the same Agent Engine session; `kind` is Primary, Secondary, or
Danger and lets every client present visual intent without guessing from
English labels or array position. `decision` separately defines whether the
choice grants or denies permission, so clients never infer authorization from
styling. The Server emits explicit values for Approve Once, Always Allow, and
Deny, and Web forwards the structured objects unchanged.

Work session schema v9 durably projects the approval ID, tool, bounded reason,
bounded advisory, and at most five validated choices. Duplicate or empty
values are discarded, empty cards receive safe defaults, and an Awaiting
Approval v5-v8 snapshot receives a recoverable migrated card. Unknown response
values cannot mutate the pending state. A Deny decision resumes the Agent
without presenting the action as approved or as verification; permitted
responses enter Verifying and then resume through the existing session.

The GPUI Approval panel now renders the advisory separately and uses native
Primary, Secondary, and Danger buttons for each choice. It no longer collapses
the shared card into one hard-coded `Allow and Continue` action.

## Verification and process output

Runtime Event protocol v6 adds `ProcessOutput` for completed Bash calls. It
carries the paired call ID, redacted command, combined output, exit code,
duration, truncation state, and Command or Verification classification. Common
test, check, lint, and build commands are classified as verification evidence;
the classification is presentation metadata and does not alter execution or
success semantics.

The shared executor redacts both command and result before retaining a 16 KiB
head/tail window, preserving the failure tail instead of keeping only a prefix.
Non-process tools do not emit the event. Web forwards the same structured event.
Work applies secret redaction and a second 20 KiB bound at its trust boundary,
retains at most 50 process records, and persists exit/duration evidence in Work
session schema v10.

The native right column is now scrollable and contains a dedicated
`Verification / Process Output` panel. It presents the command, bounded output,
exit code, duration, truncation marker, and classification independently from
the short Tool Activity preview. The left timeline and right evidence column
also use GPUI Component scrollbars so long plans, approval cards, and command
evidence remain reachable without growing the window beyond the display.

After rebuilding and signing the macOS bundle, Computer Use started Demo and
visually verified the populated 1180×760 layout: all three styled approval
choices were visible, the verification card showed `cargo check`, exit 0,
842 ms, and its output, and the file panel remained reachable below it. A
coordinate click on the native Danger button dispatched `Deny`; the durable
timeline recorded `Approval response: Deny`, the approval card cleared, and
the demo reached its final response. This run also exposed a synthetic-plan
fixture inconsistency, so Demo now emits a final `PlanUpdated` before completion
instead of leaving an active marker on a completed task.

The desktop prevents starting a second real or demo run while a run is active.
Superseding only the UI generation would leave the previous Agent executing
side effects in the background, so parallel starts remain rejected. The Stop
action now sends a control message to the worker, which delegates to the same
`run_control` registry used by Web, chat, and scheduler adapters. The worker
retries across the short run-registration race, and an integration test proves
that a pending model call is interrupted and emits the shared `Cancelled`
event. Demo cancellation invalidates its local event generation separately.

Workspace selection uses GPUI's native cross-platform directory prompt rather
than a new dialog dependency. The canonical path is validated by the pure Work
application layer and persisted across restarts. Visual inspection caught that
a Finder-launched macOS app can have `/` as its process directory, making an
automatic launch-directory fallback dangerously broad. A new install and a
missing saved path now enter a safe unselected state and real execution is
blocked until the user explicitly chooses a directory. The Work snapshot schema
was first raised to v6 for structured artifacts, v7 for durable review state,
v8 for Agent-owned plans, v9 for structured approvals, and is now v10 for
process evidence. Newly added
fields default safely when loading v5-v8 snapshots,
which are upgraded without losing the task. Earlier
Phase 0 and transitional single-session snapshots migrate to a blank English
local Work session with stable identity and timestamps.
The sidebar exposes only the shared Config's provider, model, and
path/error state, never credentials. Real launch is blocked until the offline
configuration loads successfully; online model compatibility remains a
separate validation concern.

## Packaging evidence after runtime linkage

The native bundle now includes the production runtime rather than only the
GPUI projection:

```text
debug .app                         260 MB
release .app                        55 MB
release build (cold, Thin LTO)   6m 02s
Info.plist lint                      passed
ad-hoc strict code-sign verify       passed
LaunchServices debug launch          passed
```

The release size remains viable for an early desktop build, but the cold build
time and dependency surface confirm that linking the whole Server root crate is
transitional. A later Phase 1/3 extraction should move the channel-free runtime
assembly into a smaller crate while preserving the same application-service
API. This is a build-boundary optimization, not permission to duplicate the
Agent Engine.

Visual and accessibility inspection passed after the test Mac was unlocked.
Computer Use verified the v4 blank English session, safe `Not selected`
workspace state, English status/plan/action text, and disabled Run/Stop/Approval
actions. It also activated `Select Workspace` and confirmed that GPUI opened the
native macOS directory picker with an English confirmation action. The first
visual pass directly exposed and drove removal of the unsafe `/` launch-directory
fallback and a transitional mixed-language snapshot. A scripted Demo run then
verified English task, plan, event, status, and artifact projections and exposed
one remaining fake `~/github/microclaw` workspace; the demo fixture no longer
claims a workspace the user did not select.

## Multi-session history and recovery

The desktop no longer writes one `spike-session.json` or sends every task to
`desktop-default`. `WorkSessionStore` owns an atomic index and one versioned
snapshot per stable session ID. The ID is also the Headless Runtime session key,
so recent tasks restore the matching Agent Engine conversation without leaking
history between desktop tasks. IDs are validated before becoming paths, the
index is capped at 100 entries, and recent tasks are ordered by durable update
time.

The GPUI sidebar exposes New Task and recent-session actions with status labels.
Draft edits persist after a 350 ms debounce; switching sessions first saves the
current draft. A snapshot left Running or Verifying after process exit is
projected to the explicit Interrupted state on reopen and can be retried through
the normal shared runtime. AwaitingApproval is not incorrectly marked
Interrupted because its Agent turn has already paused at a durable boundary.

Computer Use exercised the multi-session flow with two named drafts: debounce
save updated Recent Tasks, New Task created a distinct entry, selecting the
older entry restored its input and projection, and a full process restart
restored the active session plus both indexed tasks. Attempts to visually hit
the short Demo's Running crash window were overtaken by its durable approval
pause because desktop-exit/system-approval latency exceeded the demo interval;
therefore Interrupted recovery is claimed from the focused store integration
test, not from that visual run. The visual restart did confirm that an approval
pause remains AwaitingApproval rather than being mislabeled Interrupted.

## Structured activity and artifacts

The desktop now renders Tool Activity, File Changes / Artifacts, subagent
lifecycle, and Final Response from dedicated bounded fields rather than parsing
the human-readable event timeline. Tool input/result previews and persisted
diffs pass through the shared secret redactor. Artifact opening canonicalizes
both workspace and target and rejects unavailable paths, absolute escapes, and
symlink escapes outside the selected workspace.

Computer Use exercised the complete English Demo flow on macOS: the task
paused at approval with a call-ID-paired successful `read_file` activity and a
standalone `demo-output.md` diff, then completed all four plan steps and showed
the final response after approval. Clicking the synthetic artifact without a
selected workspace did not open an external path. The same run exposed a v5
snapshot deserialization regression; defaulted v6 fields plus the focused v5
migration fixed it, and the existing recent sessions loaded cleanly after
restart.

## Conversation-first desktop information architecture

The initial native shell proved runtime projection, but its main column read as
a run monitor: the composer sat above a plan and event feed, while the final
answer was buried in the artifacts inspector. That hierarchy is incorrect for
a general Work product. A Work task is a conversation that can execute, not a
dashboard that happens to accept a prompt.

The Phase 1 desktop hierarchy is now:

1. **Threads and workspace context** in the left rail. A thread is the durable
   unit of work and maps to one shared Agent Engine session.
2. **Conversation** in the dominant center surface. User turns, assistant
   responses, and the in-progress assistant draft remain readable as a single
   continuous exchange. The bottom composer starts, steers, or continues the
   same thread according to runtime state.
3. **Work inspector** on the right. Plans, approvals, verification evidence,
   file changes, and review controls support the conversation without replacing
   it. Approval can demand attention, but it remains part of the current thread.

Work snapshot schema v11 adds bounded, durable user/assistant messages and a
coalesced assistant draft. It deliberately does not create a desktop-specific
agent loop: text still arrives through the shared Runtime Event protocol and
final responses still come from the shared Agent Engine. Future multi-agent
work should add child-run activity and thread switching around this stable
center, not turn the home page into a grid of agent status cards.

Computer Use verified the rebuilt GPUI app after terminating stale test
instances: the center surface restored the migrated user prompt and assistant
answer as conversation cards, the composer remained anchored below the thread,
and Plan, Approval, Verification / Process Output, and Artifacts occupied the
scrollable inspector. This visual pass also caught that older schema snapshots
would otherwise render an empty conversation; schema v11 migration now derives
the initial user and assistant turns from their legacy task and final response.

The next native pass removed the transitional `Continue Task` mode. Snapshot
schema v12 separates the last submitted task from the unsent composer draft;
completed threads now accept the next turn directly, preserve all earlier
messages, and clear the composer after submission. Approval choices moved into
the conversation at the pause point, while the right inspector remains focused
on plan, verification, and artifacts. Computer Use exercised this exact path:
it ran the Demo to an inline three-option approval, denied it, entered a new
follow-up, started the Demo again, and verified both user turns remained visible
while the composer cleared and the new inline approval appeared below them.

## Multi-file change review

Work snapshot schema v13 adds an explicit selected-file projection. Each
successful shared `FileDiff` event updates the bounded file collection and
selects the newest change; selecting another known path is a validated Work
command and survives snapshot reload. The GPUI inspector now combines the file
list, `+added/-removed` and truncation metadata, safe file opening, a bounded
scrollable unified diff, and accept/revert state. Added and removed lines use
theme-derived success and danger backgrounds while headers and context remain
neutral.

Computer Use verified the two-file Demo in a maximized native window. It showed
`demo-output.md` and `src/work.rs`, initially rendered the selected Rust diff
with red/green line treatment, then activated the Markdown entry through its
accessible button and immediately replaced the selected styling, filename, and
diff body. The focused persistence test additionally proves invalid paths are
rejected and a valid selection restores after reload.

## Provider connection diagnostics

The first-run settings path previously proved only that YAML parsed. The Work
runtime now owns an asynchronous provider diagnostic that creates the same
provider abstraction as the Agent Engine and sends one minimal, tool-free
request. A 20-second timeout bounds the operation. The result reports provider,
model, latency, and a bounded visible response; errors pass through both an
explicit configured-credential replacement and the shared secret redactor.
GPUI only starts the application-service operation and polls its result channel.

Two loopback HTTP tests exercise the actual OpenAI-compatible boundary. The
success fixture verifies the `/v1/chat/completions` path, Bearer header, model,
prompt, and response decoding. The 401 fixture verifies an error returns to the
caller without the configured credential. Computer Use verified the English
native settings page, masked API-key field, save-first disabled state, and the
new accessible Test Connection action. No live credential was read or sent
during this validation.

## Recovery-ready retry semantics

Separating the composer draft from submitted turns exposed a recovery defect:
an Interrupted session restored with an empty composer, while the old launch
path required non-empty composer text. Retry is now a first-class Work command
for Interrupted, Failed, and Cancelled states. It validates that a prior task
exists, preserves the transcript and stable thread title, avoids inserting a
duplicate user message, and resets partial assistant draft, plan, activity,
process output, file changes, approval, checkpoint, and review projections
before the shared runtime is relaunched with the last submitted task.

Focused projection coverage constructs a running turn with streamed partial
text and a file diff, marks it Interrupted, retries it, and proves conversation
identity is retained while stale run state is removed. Store coverage persists
a Running snapshot, restores it as Interrupted with an empty composer, and
proves the recovered snapshot accepts Retry. The native Demo interval was also
lengthened to make active-state inspection practical and no longer seeds its
conversation through the old synthetic snapshot path.

## Deterministic process-level recovery

Recovery is now verified across operating-system process boundaries instead of
depending on GUI timing. The no-GPUI harness exposes three test-only modes over
the real `WorkSessionStore`: the first persists a Running snapshot containing a
partial provider response and file diff, then aborts; the second process loads
the same store, which projects the task to Interrupted; the third loads that
Interrupted snapshot, applies `RetryTask`, persists, and emits the result.

The parent integration test asserts the crash process fails, the recovery
process retains the task, one user message, partial draft, and file change, and
the retry process keeps the same session ID and identical transcript while
returning to Running with partial draft, file changes, plan, and approval state
cleared. This closes the deterministic crash/restart evidence gap left by the
short native Demo timing window.
