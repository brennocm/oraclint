# NS-DB-001: SQL query logging enabled

| Severity | Target | Status | CWE |
|---|---|---|---|
| medium | config | stable | CWE-532 |

## Description

Fires when `Database.LogQueries = true` (default `false`).

## Why it matters

The node then logs the SQL statements it runs (at debug level). Statements can
contain job specs, bridge configuration and other data that should not be
copied into log storage. The node documentation itself recommends enabling
statement logging on Postgres instead when a full SQL log is needed.

## Vulnerable example

```toml
[Database]
LogQueries = true
```

## Fixed example

```toml
[Database]
# LogQueries removed (defaults to false)
```

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/CONFIG.md#logqueries
