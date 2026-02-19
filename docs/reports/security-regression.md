# Security Regression Pack

## Target

- auth bypass prevention
- scope enforcement correctness
- hook failure isolation

## Executed Checks

1. unauthenticated access to protected web APIs returns `401`
2. read-only scope cannot call write/admin APIs (`403`)
3. disabled API key cannot authenticate
4. failed/invalid hook output does not crash runtime
5. blocked hook returns deterministic user-facing message

## Command Set

```sh
cargo test -q
```

## Result

- pass
