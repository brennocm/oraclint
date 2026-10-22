# NS-AUD-001: Audit logs forwarded over plaintext

| Severity | Target | Status | CWE |
|---|---|---|---|
| low | config | stable | CWE-319 |

## Description

Fires when `AuditLogger.Enabled = true` and `AuditLogger.ForwardToUrl` uses
`http://` to a non-internal host.

## Why it matters

Audit events record security-relevant operator actions. Sent over plaintext
they can be read, and an attacker on the path can drop or alter them, which
undermines the point of an audit trail. Any `AuditLogger.Headers` (often an
authorization token) travel in cleartext too.

## Vulnerable example

```toml
[AuditLogger]
Enabled = true
ForwardToUrl = 'http://audit.example.com/events'
```

## Fixed example

```toml
[AuditLogger]
Enabled = true
ForwardToUrl = 'https://audit.example.com/events'
```

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/CONFIG.md#auditlogger
