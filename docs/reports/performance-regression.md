# Performance Regression Pack

## Target

- request limiter behavior under concurrent web requests
- stream replay behavior under reconnect
- metrics endpoints under active traffic

## Executed Checks

1. same-session concurrency guard returns `429` for overflow
2. rate window resets correctly after cooldown
3. stream replay with `last_event_id` returns expected deltas
4. metrics endpoints return data after request load

## Command Set

```sh
cargo test -q
```

## Result

- pass
