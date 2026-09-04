---
id: sdk-workers
title: Local and remote Workers
description: Scale or isolate MicroClaw SDK execution using one Worker contract.
---

# Local and remote Workers

Workers move run execution behind a capacity-aware boundary without changing
the Agent, Run, event, control, or result model used by the host application.
Start without a Worker unless you need queueing, process isolation, or remote
capacity.

## Local Worker

`LocalWorker` executes against an in-process Runtime. It reports active and
queued work, labels, capacity, health, and draining state. During shutdown:

1. mark the Worker as draining;
2. stop submitting new runs;
3. call `wait_for_idle()`;
4. stop the process after active work reaches a terminal state.

Submissions made while draining or unavailable return an explicit
`Unavailable` error.

## Remote Worker

Enable the transport without the full Agent Engine using `remote-worker`, or
use `full`, which already includes it:

```toml
microclaw-sdk = {
  version = "0.5",
  default-features = false,
  features = ["standard", "remote-worker"]
}
```

`WebSocketWorkerTransport` connects an SDK client to an authenticated
`WorkerHost`. Both sides exchange versioned `WorkerCommand` and `WorkerFrame`
messages. Validate `WORKER_PROTOCOL_VERSION` during connection setup and reject
incompatible peers explicitly.

Configure bounded reconnect behavior when the default three attempts and
incremental 250 ms backoff do not fit the host:

```rust
use std::time::Duration;
use microclaw_sdk::{RemoteWorker, RemoteWorkerOptions};

let options = RemoteWorkerOptions::default()
    .max_reconnect_attempts(5)
    .reconnect_backoff(Duration::from_millis(500));
let worker = RemoteWorker::connect_with_options(transport, options).await?;
```

Reconnect resumes after the last delivered sequence and resends an unacknowledged
control request. Attempts are bounded; exhaustion produces a retryable
`RuntimeErrorCode::Unavailable` result.

## Reconnection and replay

Remote runs keep the same run and session identity across reconnects. A client
resumes from its last observed event sequence; the host retains a bounded event
history for replay. If the requested history has expired, surface the retryable
error and start a new run or recover from application-level state—never pretend
the missing event range was delivered.

## Deployment checklist

- authenticate every Worker connection;
- use TLS at the deployment edge;
- set capacity based on model and tool workload, not socket count;
- propagate cancellation and approval decisions;
- monitor health, queue depth, reconnects, and expired replay requests;
- drain before deploys or shutdowns;
- keep tool filesystem and network policy on the Worker that executes them.

Use remote Workers as an execution boundary, not as a second orchestration
system. The application should continue to program against `Worker` and
`RunHandle` regardless of placement.
