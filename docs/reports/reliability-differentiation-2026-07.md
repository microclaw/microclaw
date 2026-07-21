# Reliability Differentiation Report

Date: 2026-07-21

## Positioning

MicroClaw should compete on **verifiable delivery reliability and operational simplicity**, not on an unqualified claim that it has more features than OpenClaw, NanoClaw, or ZeroClaw.

The product promise is: once a reply is accepted for outbound delivery, MicroClaw preserves the complete logical message, makes delivery progress durable, resumes unfinished work after restart, and exposes the remaining risk through one diagnostic command.

## Evidence in the current implementation

1. A parent delivery record stores the complete logical message before channel I/O begins.
2. Ordered child records track each chunk with a stable idempotency key and independent retry state.
3. Text splitting preserves every source byte, including newlines at chunk boundaries.
4. Startup recovery returns interrupted `sending` chunks to a resumable state.
5. Scheduled execution and outbound delivery have separate durable states, so a completed task is not mistaken for a delivered message.
6. Shared outbound sanitization removes recognizable reasoning and tool-trace wrappers before text reaches a channel adapter.
7. `microclaw doctor delivery` reports unfinished, retrying, and terminally failed deliveries without modifying runtime state.

## Point-in-time validation

The P0 validation on 2026-07-21 covered:

- a real Weixin reply split into three chunks and reconstructed exactly, including all newlines;
- a one-shot scheduled task that executed once and produced a delivered Weixin message;
- a synthetic interrupted delivery that resumed after process restart with its idempotency key unchanged;
- clean delivery diagnostics after the tests, with no unfinished or terminally failed logical deliveries;
- GitHub CI and Extended CI on Linux, macOS, and Windows after the final chunk-boundary fix.

Handset display remains a human acceptance check because server-side acknowledgements cannot prove how the Weixin client rendered every message.

## Claims we can make

- Delivery state is durable and inspectable.
- Interrupted chunked delivery is resumable.
- Scheduled results are not discarded merely because immediate channel delivery fails.
- Long-message reconstruction is covered by automated tests and a real Weixin delivery test.
- Operators can inspect delivery health with one read-only command.

## Claims that still require comparative benchmarks

Do not yet claim that MicroClaw is universally “more reliable than ZeroClaw” or any other project. A defensible comparative claim needs the same failure-injection suite, channel, payloads, retry window, and release versions across projects.

The next useful benchmark is a repeatable reliability scorecard covering process termination, network timeout, rate limiting, duplicate acknowledgement, malformed model wrappers, and payloads above each channel's native limit. Publish pass/fail evidence and recovery time rather than a subjective feature count.
