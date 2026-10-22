# NS-LOG-001: Debug log level

| Severity | Target | Status | CWE |
|---|---|---|---|
| low | config | stable | CWE-532 |

## Description

Fires when `Log.Level = 'debug'` (default `info`, case-insensitive).

## Why it matters

Debug logs record far more detail about requests, job runs and internal state
than production needs. Logs are commonly shipped to third-party systems with
wider access than the node itself, and the extra volume makes real errors
harder to spot. `Log.Level` controls console output only; file logging has its
own settings.

## Vulnerable example

```toml
[Log]
Level = 'debug'
```

## Fixed example

```toml
[Log]
Level = 'info'
JSONConsole = true
```

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/CONFIG.md#log
