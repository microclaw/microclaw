# microclaw-work-app

Framework-independent application and domain layer for MicroClaw Work.

This crate owns:

- foreground Work task lifecycle;
- plan, progress, approval, verification, and completion state;
- bounded event projections;
- versioned session snapshots and persistence format.

All lifecycle changes enter through `WorkSessionSnapshot::apply(WorkCommand)`.
The command reducer returns a `CommandOutcome` and rejects invalid transitions,
such as approving a task that is not waiting for approval. UI and runtime
adapters must not modify lifecycle fields directly.

It must not depend on GPUI, operating-system UI APIs, LLM providers, channel
SDKs, or Server transports. Desktop views send commands into this layer and
render its projections. The production shared agent runtime will be attached
through explicit application services in Phase 1; it must not be called
directly from GPUI views.
