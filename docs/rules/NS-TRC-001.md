# NS-TRC-001: Traces exported unencrypted to a remote collector

| Severity | Target | Status | CWE |
|---|---|---|---|
| medium | config | stable | CWE-319 |

## Description

Fires when `Tracing.Enabled = true`, `Tracing.Mode = 'unencrypted'` (default
`tls`) and `Tracing.CollectorTarget` is not a loopback, private or internal
host (see NS-RPC-001 for the definition).

## Why it matters

Traces describe what the node is doing (job runs, external calls, timings)
and are sent continuously. The node intends unencrypted traces only for local
collectors ("Unencrypted traces can not be sent to external networks"), but in
v2.69.0 its check (`isValidLocalURI`) only verifies that the target is a
syntactically valid `host:port`, so a public collector is accepted.

## Vulnerable example

```toml
[Tracing]
Enabled = true
Mode = 'unencrypted'
CollectorTarget = 'otel.example.com:4317'
```

## Fixed example

```toml
[Tracing]
Enabled = true
Mode = 'tls'
CollectorTarget = 'otel.example.com:4317'
TLSCertPath = '/certs/otel.pem'
```

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/CONFIG.md#tracing
- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/core/config/toml/types.go
