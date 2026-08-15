---
id: observability
title: Observability
sidebar_position: 22
---

MicroClaw observability surfaces:

- `/api/metrics`
- `/api/metrics/history`
- `/api/usage`
- `/api/memory_observability`

Export:

- OTLP exporter over HTTP/protobuf
- bounded queue + retry backoff + batched export

Primary reference: `docs/observability/metrics.md`.
