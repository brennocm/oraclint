# NS-SEC-002: Credential in AuditLogger headers

| Severity | Target | Status | CWE |
|---|---|---|---|
| medium | config | stable | CWE-260 |

## Description

Fires for each `AuditLogger.Headers` entry whose header name looks like a
credential (`Authorization`, `*Token*`, `*Api-Key*`, `*Secret*`, `Cookie`,
`*Password*`) and has a value.

## Why it matters

`AuditLogger.Headers` is part of the config schema and has no `secrets.toml`
equivalent, so the credential for the audit endpoint ends up in the config
file, which is usually committed and shared. Anyone with read access to the
repository can then write fake events into, or read from, the audit system.

## Vulnerable example

```toml
[AuditLogger]
Headers = ['Authorization: Bearer <token>']
```

## Fixed example

Keep the `[AuditLogger]` section in a separate config file that is not
committed, or pass it through the `CL_CONFIG` environment variable (the node
applies it last) from a secret manager. Rotate a token that was committed.

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/CONFIG.md#headers
