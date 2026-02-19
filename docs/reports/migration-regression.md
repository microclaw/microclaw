# Migration Regression Pack

## Target

- schema migration safety for existing deployments
- backward compatibility of session data
- auth and metrics table creation on upgrade

## Migration Points

- v5: auth tables
- v6: session fork columns
- v7: metrics history table

## Executed Checks

1. startup on existing DB applies migrations without manual SQL
2. pre-existing session rows remain readable
3. new auth APIs operate after migration
4. metrics history insert/query works post-migration

## Command Set

```sh
cargo test -q
```

## Result

- pass
