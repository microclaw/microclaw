# Product direction — MicroClaw Work and Server

Status: **Active** · Date: **2026-08-24**

This document records the product direction after reviewing MicroClaw's current
capabilities, packaging boundary, recent competitor development, and public
roadmaps. It is a direction and sequencing document, not authorization to begin
implementation. Individual workstreams still require scoped plans and normal
review before code changes start.

## 1. Decision

MicroClaw should not compete by adding the largest number of channels or agent
features. Its next product phase should turn the existing runtime into an
installable and understandable product:

> A lightweight, reliable, self-hosted personal and small-team agent runtime
> that installs in minutes, runs locally or on a VPS, and deploys multiple
> isolated agents through one control surface.

The recommended sequence is:

1. Build `microclaw-work`, a native, pure-Rust macOS, Windows, and Linux work
   companion using GPUI and GPUI Component, with its own foreground,
   interactive loop. Hold macOS and Windows to release quality first while
   Linux begins as a continuously built preview.
2. Productize existing subagent and orchestration primitives as persistent,
   named agent profiles and bounded team templates.
3. Make local, VPS, and third-party cloud deployment easy to connect and
   operate remotely.
4. Consider a native mobile client or managed runtime only after usage data
   demonstrates that either investment is necessary.

This direction preserves the current architectural rule: one shared,
channel-independent agent/runtime layer with thin interaction and delivery
adapters around it.

## 2. Why this is the next problem

MicroClaw already contains most of the difficult runtime machinery:

- a provider-neutral multi-step agent loop;
- tools, skills, plugins, MCP, ACP, and A2A;
- durable sessions, checkpoints, restart recovery, scheduler, and outbox;
- memory, hooks, governance, approvals, audit, and observability;
- native and ACP-backed subagents, specialist profiles, bounded concurrency,
  fan-out/fan-in, cancellation, retry, and completion contracts;
- Web UI, CLI, HTTP/SSE/WebSocket APIs, and many chat adapters.

The gap is no longer primarily capability. The first-use path still exposes the
complexity of a professional runtime: installation, setup, configuration,
service lifecycle, provider credentials, channels, workspaces, agents, and
subagents. The product needs a simpler entrance and a clearer operating model.

The competitive direction supports this reading:

- OpenClaw is deepening its Control UI, session management, device placement,
  structured approvals, and multi-agent bindings.
- Hermes ships a native desktop application for macOS, Windows, and Linux with
  onboarding, settings, file previews, tool activity, and voice around the
  same runtime.
- Nanobot bundles its Web UI, improves guided setup and mobile Web use, and
  describes its goal as a lightweight personal agent companion rather than a
  minimal kernel alone.
- ZeroClaw has shipped a Tauri desktop surface and dashboard-led upgrades.
- NemoClaw is investing in buildless managed onboarding and container setup.

The category has moved from proving that an agent can call tools toward making
the runtime installable, controllable, observable, and trustworthy.

## 3. Product architecture

The product should have two explicit runtime personalities built on shared core
crates:

```text
microclaw-work                         microclaw-server
native GPUI work companion             always-on agent service
foreground and user-steered            background and unattended
workspace, plans, diffs, artifacts      channels, schedules, delivery
        |                                      |
        +---------- shared core runtime -------+
                    providers, messages,
                    tools, policy, memory,
                    checkpoints, contracts
```

The implementation principles are:

- `microclaw-work` and `microclaw-server` have distinct loop policies and task
  lifecycles, but share provider-neutral messages, provider adapters, tool
  execution, policies, checkpoints, memory primitives, and completion contracts.
- The Work loop is foreground, workspace-aware, continuously steerable, and
  optimized for plans, progress, file changes, verification, and artifacts.
- The Server loop is background, channel-oriented, durable, and optimized for
  scheduled work, long-running services, delivery, recovery, and persistent
  multi-agent routing.
- The two products must not fork or duplicate the provider-neutral agent engine.
- `microclaw-work` is a native Rust application, not a browser shell and not a
  Web UI wrapper. It uses GPUI for the application surface and GPUI Component
  for its initial component system.
- GPUI entities own presentation state only. Durable task, session, approval,
  workspace, and artifact state remain in shared application/runtime services
  and SQLite so that window lifecycle never becomes task lifecycle.
- `microclaw-server` remains headless-first and may serve a Web management UI
  for remote access, operations, onboarding, and mobile/PWA use.
- Mobile is initially a remote client, not an on-device runtime.
- Cloud initially simplifies deployment and connectivity; it does not duplicate
  the runtime in a new multi-tenant service.
- Multi-agent work builds on existing subagent, ACP, A2A, and completion-contract
  primitives instead of introducing a parallel orchestration engine.

## 4. `microclaw-work` before native mobile

### 4.1 Desktop work companion

The highest-value product investment is `microclaw-work`, a native desktop work
companion for macOS, Windows, and Linux. Its application and UI should be pure Rust,
using GPUI plus GPUI Component rather than Tauri or an embedded browser. The
product has its own foreground task loop rather than serving only as a control
center for `microclaw-server`.

Its core workflow is:

```text
open a workspace
-> describe a task
-> review a plan
-> watch tools and file changes
-> steer the task while it runs
-> review diffs and artifacts
-> verify and accept the result
```

A first release should provide:

- signed and notarized macOS installation;
- signed Windows installer;
- a continuously built Linux preview, promoted to an equal release tier only
  after packaging and platform QA are sustainable;
- guided provider/model and credential onboarding;
- workspace selection and local project context;
- foreground tasks with plan, progress, interruption, and resume;
- file changes, diffs, terminal activity, verification, and artifacts;
- explicit approval of local side effects;
- invocation of local tools and ACP-compatible workers;
- creation of the first work session and first completed task;
- optional background continuation after the window closes;
- system tray or menu-bar presence;
- logs, diagnostics, upgrade, and task-recovery guidance;
- connection to an existing remote MicroClaw instance.

The first release should not attempt to become a complete IDE, local-model
manager, voice stack, canvas platform, plugin marketplace, or administration UI
for every Server feature. It should first make one desktop work loop excellent.

### 4.2 Native UI architecture

The desktop application should be introduced as a workspace member, with a
small compatibility layer around GPUI rather than spreading framework-specific
types through the runtime:

```text
apps/microclaw-work
  windows, views, commands, keyboard routing, native integration
             |
             v
microclaw-work-ui
  GPUI/GPUI Component adapter, theme, reusable product components
             |
             v
microclaw-work-app
  workspace/task/application services, projections, UI event stream
             |
             v
existing shared runtime crates
  agent engine, providers, tools, policy, storage, checkpoints
```

The exact crate names are provisional. The important boundary is that GPUI
views render projections and send commands; they do not directly own the agent
loop, database, provider calls, or tool execution. A bounded event stream and
periodic snapshots should feed the UI so a high-volume tool run cannot block
rendering or require replaying an unbounded transcript.

Use GPUI Component for the common product vocabulary before writing custom
widgets: buttons, forms, menus, dialogs, tabs, dock layout, lists, tables,
Markdown, code viewing, notifications, and themes. Drop down to `gpui-base` or
custom GPUI elements only for a measured product requirement. This avoids
turning the first release into a design-system project.

The first information architecture should stay work-oriented:

- onboarding and provider setup;
- workspace and recent-task sidebar;
- primary conversation/work canvas;
- plan and live progress timeline;
- tool activity, process output, files, diffs, and artifacts;
- a persistent approval center;
- diagnostics, models, policies, and Server connections.

A process-output panel is sufficient for the first vertical slice. A complete
PTY terminal emulator, IDE-grade editor, arbitrary dock customization, and
multi-window workspace system should be added only after the core loop works.

### 4.3 GPUI adoption gate

GPUI and GPUI Component are attractive because they preserve a single Rust
toolchain, native rendering, a small distribution boundary, and direct access
to the existing runtime. They are also fast-moving dependencies currently
consumed from Git, so this choice needs an explicit technical gate before the
team commits the whole desktop roadmap to it.

Run a two-week spike that pins exact revisions and verifies on real macOS and
Windows machines:

- Chinese and English input, IME composition, selection, clipboard, shortcuts,
  and accessibility;
- window lifecycle, sleep/wake, high-DPI scaling, multiple monitors, dark mode,
  drag and drop, and file dialogs;
- streaming Markdown and tool events without layout churn;
- virtualized histories of at least 10,000 representative events;
- code/diff rendering for realistically large files;
- process cancellation, crash recovery, and task continuation after a window
  closes;
- signed `.app`/DMG and signed Windows installer production;
- GPU/renderer behavior on the oldest supported hardware and remote desktops.

Exit the spike only when the same vertical prototype can open a workspace,
stream an agent task, request approval, show a diff, and recover it after
restart on both operating systems. Keep the framework behind the adapter crate,
pin revisions in the lockfile, schedule deliberate upgrades, and run the
cross-platform smoke suite on every dependency update. If critical Windows,
IME, or accessibility behavior cannot be made reliable within the spike, make
the fallback decision before building the full UI rather than carrying an
indefinite native-framework rewrite.

### 4.4 Work and Server cooperation

`microclaw-work` and `microclaw-server` should be useful independently and able
to delegate to each other through a stable task protocol.

Examples:

- Work turns "check this repository every morning" into a scheduled Server
  task, while retaining a link to its status and results.
- Server delegates a development task to an online Work instance that has the
  required local workspace and tools.
- Work sends a long unattended task to Server and later resumes the result as
  an interactive desktop session.

This bridge should carry identity, workspace reference, permissions, budget,
completion contract, progress, cancellation, and result artifacts. ACP and A2A
are starting points, but the user-facing contract must remain MicroClaw-owned.

### 4.5 Mobile as a remote surface

iOS and Android are poor initial hosts for a reliable, always-on agent runtime
because of background execution limits, constrained filesystem and process
access, long-connection suspension, and app-store restrictions around dynamic
tools and plugins.

The mobile sequence should therefore be:

1. Make the existing Web UI properly responsive.
2. Add PWA metadata and installability.
3. Add secure QR-code pairing with a local or remote instance.
4. Support notifications, approvals, task status, and chat from mobile Web.
5. Build a native mobile client only if usage shows that PWA limitations block
   an important workflow.

A future native application should remain a client of a home, desktop, or VPS
runtime rather than embedding the complete runtime on the phone.

## 5. Separate Work UI from Server Web UI

The Web UI should not be bundled into `microclaw-work`. The desktop product has
a native GPUI surface and should not ship two frontend stacks. The Web UI
should remain in the standard `microclaw-server` distribution because it serves
a different job: remote onboarding, operations, administration, and mobile/PWA
access.

The current local release binary is approximately 66 MB, while `web/dist` is
approximately 1.7 MB. Removing the embedded static assets would save only a
small fraction of the binary while removing the shared onboarding, settings,
approval, status, and operational surface.

The more likely size contributors are native and statically linked runtime
dependencies, including protocol stacks, TLS, channel SDKs, SQLite, and PDF
rendering. Many of these dependencies are currently unconditional even though
the feature table appears minimal.

Before changing packaging, measure at least:

- binary contribution by crate and symbol;
- cold-start time;
- idle resident memory;
- clean-build time;
- container image size;
- behavior with representative feature combinations.

The intended distribution families are:

| Distribution | Intended user | Contents |
|---|---|---|
| `microclaw-lite` | VPS, containers, embedding, advanced operators | Agent loop, SQLite, API, foundational tools, and a deliberately small channel set; no heavy optional rendering or local UI |
| `microclaw` | Default personal installation | Lite foundation plus Web UI, common channels, scheduler, skills, and MCP |
| `microclaw-full` | Broad or specialized deployment | Complete channel and optional integration set, including heavier features such as Matrix, PDF, and vector retrieval |

For the next major Server version, classify each third-party adapter using
actual activation, maintenance burden, failure rate, build contribution, and
community ownership. Keep the core small; ship only high-use integrations in
the standard package; move low-use or heavy adapters behind features, separate
packages, or plugins; and announce deprecation for at least one major-version
cycle before removal. The goal is a sustainable compatibility boundary, not a
one-time deletion of old integrations.

The standard Server distribution should continue to include Web UI. A real
lite build requires making heavyweight crates and capability families optional,
not only excluding static Web assets. Conversely, Work should not link every
Server channel, protocol adapter, or heavy rendering feature. Its dependency
graph should contain the shared runtime plus only capabilities required by the
local work loop.

Do not pursue feature parity between the two UIs. Work owns workspace tasks,
plans, diffs, approvals, and artifacts. Server Web owns agents, channels,
schedules, health, remote sessions, and operational settings. Shared concepts
should use common API/domain types, not a shared frontend implementation.

## 6. Cloud direction: deployment before SaaS

MicroClaw should not start by operating a full multi-tenant agent SaaS. That
would immediately add credential custody, tenant isolation, billing, abuse
prevention, storage, backups, network-egress governance, migrations, and uptime
commitments. It would consume the team's capacity and weaken the lightweight,
self-hosted position.

The first cloud work should make user-owned deployments easy:

- documented Docker Compose deployment;
- one-click templates for suitable platforms such as Railway, Render, and Fly;
- straightforward deployment to a VPS, NAS, or home server;
- guided Tailscale or Cloudflare Tunnel connectivity;
- persistent-volume, backup, and upgrade defaults;
- QR-code pairing from desktop or mobile Web.

A later optional cloud control plane may provide instance discovery, encrypted
remote connectivity, status, alerts, version notifications, deployment
templates, and an optional relay. Its default role should not include storing
conversation content, holding model credentials, or executing user tools.

A fully managed runtime should be considered only when evidence shows that
self-deployment remains a major adoption blocker and that users are willing to
pay for hosted operation and its trust model.

## 7. Multi-agent direction: productize what exists

MicroClaw already has substantial multi-agent execution machinery. The next
step is not a new generic multi-agent engine. It is a user-facing model for
persistent, isolated agents.

### 7.1 Named agent profiles

Introduce a first-class `agents` configuration and management surface. Each
named agent should have independently scoped:

- workspace and identity files;
- memory namespace and session history;
- provider, model, and token budget;
- tool and network policy;
- credentials;
- channel/account bindings;
- scheduler and heartbeat configuration.

An illustrative configuration shape is:

```yaml
agents:
  personal:
    name: Personal Assistant
    workspace: ~/.microclaw/agents/personal
    model: claude-sonnet
    policy: personal

  developer:
    name: Development Agent
    workspace: ~/github
    model: codex
    policy: development

  researcher:
    name: Research Agent
    workspace: ~/.microclaw/agents/researcher
    model: gemini
    policy: research
```

This is a conceptual shape, not a committed configuration schema.

### 7.2 Bounded team templates

After named profiles, expose a small set of understandable templates that reuse
the existing orchestration path:

- software: planner -> implementer -> reviewer;
- research: parallel investigators -> synthesizer;
- content: researcher -> writer -> editor;
- operations: monitor -> investigator -> responder.

Users should be able to select a template, choose models and a workspace, review
permissions and budget, and deploy. The first version should avoid a free-form
drag-and-drop DAG editor. Bounded templates, declared completion contracts, and
visible task timelines are easier to understand, test, budget, and recover.

## 8. Recommended delivery sequence

### Phase 0 — define and measure the first-use funnel

Before substantial UI implementation:

- define the default journey: download -> install -> provider configured ->
  first agent created -> first successful response -> service installed;
- add opt-in, privacy-preserving product telemetry for this journey;
- record operating system, installation method, setup failures, service health,
  and seven-day survival without collecting conversation content;
- define release-quality targets for installation and first response.

Suggested decision metrics include setup completion, first-response success,
time to first response, service-install success, seven-day active installation,
and mobile-Web share. Targets require a baseline and are intentionally not
invented in this document.

### Phase 1 — GPUI spike and `microclaw-work` vertical slice

Estimated scope: a two-week adoption spike followed by 6–8 weeks for the first
vertical slice if the gate passes.

1. Pin GPUI and GPUI Component revisions and pass the macOS/Windows adoption
   gate, including IME, accessibility, rendering, recovery, and packaging.
2. Add the GPUI compatibility/component boundary and application projections.
3. Extract and stabilize the shared agent-runtime boundary without duplicating
   the existing engine.
4. Deliver one end-to-end native workflow: open workspace, start task, review
   plan, observe tools, approve a side effect, inspect a diff, verify, and
   accept an artifact.
5. Produce macOS and Windows signed installers for `microclaw-work`.
6. Foreground workspace task model: plan, steer, pause, resume, cancel, verify,
   diff, and artifact delivery.
7. Guided onboarding and first-completed-task path.
8. Local tool approvals, diagnostics, logs, upgrade, and recovery.
9. Optional connection to `microclaw-server` without requiring it for local
   Work use.
10. Responsive remote surfaces and installable PWA where they complement Work.
11. Lite/standard/full Server size investigation and measured packaging proposal.

This phase should reuse current capabilities rather than add broad new agent
features. Its new work is the desktop task lifecycle and product experience.

### Phase 2 — persistent agents and teams

Estimated scope: 6–10 weeks after Phase 1 proves the control surface.

1. Named, isolated agent profiles.
2. Agent list and configuration in Server Web UI and `microclaw-work` where
   relevant to a desktop task.
3. Channel/account-to-agent bindings.
4. Clone, export, and import flows.
5. Three or four bounded team templates.
6. A visible Tasks/Workers surface over the current subagent timeline.
7. Per-agent policy, credentials, budgets, health, and recovery state.

### Phase 3 — deployment and remote operation

Estimated scope: 6–8 weeks after the local product path is stable.

1. Docker Compose and supported cloud templates.
2. QR-code device pairing.
3. `microclaw-work` and PWA connection to remote instances.
4. Guided private-network/tunnel setup.
5. Instance status, alerts, backups, and upgrade visibility.
6. A decision document for an optional lightweight cloud control plane.

### Phase 4 — evidence-gated expansion

Consider a native mobile client when mobile Web becomes a material share of
active use and PWA limitations measurably block approvals, notifications, or
chat. Consider a managed runtime when deployment and operations remain the
dominant source of abandonment and users demonstrate willingness to pay for a
hosted trust and reliability boundary.

## 9. Explicit non-goals for the next phase

Until Phase 1 is complete and measured, do not prioritize:

- a native iOS or Android agent runtime;
- a full multi-tenant managed-agent cloud;
- a second independent desktop agent engine or duplicated frontend stack;
- embedding the Server Web UI inside `microclaw-work`;
- building a new component library where GPUI Component already meets the need;
- a free-form multi-agent canvas;
- additional channel breadth for its own sake;
- removing Web UI from the standard build;
- meeting bots, wearables, or a broad voice stack;
- rewriting the Rust runtime for binary-size optics;
- competing on total feature count.

## 10. Decision gates

The roadmap should be adjusted using product evidence rather than competitor
star counts alone.

Before native mobile work, verify:

- the share and retention of mobile-Web users;
- frequency of mobile approvals, notifications, and task monitoring;
- concrete PWA limitations causing failed or abandoned workflows.

Before a managed runtime, verify:

- setup and deployment abandonment after one-click options exist;
- support burden attributable to self-hosting;
- demand for paid hosting, backup, and uptime;
- the team's ability to operate credential and multi-tenant security safely.

Before expanding multi-agent topology, verify:

- adoption and completion quality of named profiles and bounded templates;
- cost, latency, and recovery behavior per team run;
- whether users need arbitrary workflows or only a small number of repeatable
  team patterns.

## 11. Source notes and current evidence

Internal evidence:

- [`next-direction-2026-08.md`](./next-direction-2026-08.md) records the current
  Rust, build, frontend, and release-boundary health review.
- [`competitive-intel-update-2026-08.md`](./competitive-intel-update-2026-08.md)
  records the latest in-repository competitor scan.
- [`../reports/reliability-differentiation-2026-07.md`](../reports/reliability-differentiation-2026-07.md)
  describes the existing reliability position.
- [`../operations/concurrency-and-responsiveness.md`](../operations/concurrency-and-responsiveness.md)
  describes current multi-lane and subagent behavior.
- [`../operations/durable-coworker.md`](../operations/durable-coworker.md)
  describes current checkpoint and recovery behavior.
- [`../a2a.md`](../a2a.md) describes current instance-to-instance delegation.

External primary references:

- [GPUI Component](https://github.com/longbridge/gpui-component)
- [GPUI Component architecture](https://github.com/longbridge/gpui-component/blob/main/docs/ARCHITECTURE.md)
- [Zed, the primary GPUI application](https://github.com/zed-industries/zed)
- [Hermes Desktop](https://github.com/nousresearch/hermes-agent/blob/main/apps/desktop/README.md)
- [Hermes multi-agent roadmap](https://github.com/NousResearch/hermes-agent/issues/344)
- [Nanobot roadmap](https://github.com/HKUDS/nanobot/discussions/431)
- [Nanobot Web UI packaging](https://github.com/HKUDS/nanobot/blob/main/webui/README.md)
- [Nanobot deployment](https://github.com/HKUDS/nanobot/blob/main/docs/deployment.md)
- [OpenClaw multi-agent routing](https://github.com/openclaw/openclaw/blob/main/docs/concepts/multi-agent.md)

## 12. Confidence and unresolved inputs

This is a strategy recommendation supported by repository architecture,
packaging measurements, competitor implementation, and public plans. It is not
yet supported by MicroClaw product analytics. The most important missing inputs
are installation completion, first-response success, platform mix, seven-day
survival, deployment-related support burden, mobile-Web share, and willingness
to pay for managed operation.

Until those inputs exist, the `microclaw-work`-first and
deployment-before-SaaS choices should be treated as high-confidence, reversible
bets. Native mobile and managed runtime work should remain explicitly
evidence-gated.
