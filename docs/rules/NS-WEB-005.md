# NS-WEB-005: Long idle session timeout

| Severity | Target | Status | CWE |
|---|---|---|---|
| low | config | stable | CWE-613 |

## Description

Fires when an explicitly set idle session timeout is longer than one hour:
`WebServer.SessionTimeout` (default `15m`), plus `WebServer.LDAP.SessionTimeout`
or `WebServer.OIDC.SessionTimeout` when that authentication method is active
(defaults `15m0s`).

## Why it matters

The idle timeout decides how long a forgotten browser tab or a copied session
cookie stays usable. Operator sessions can change jobs, bridges and keys, so
the node default is short. The one-hour threshold leaves room for convenience
while catching day-long sessions.

## Vulnerable example

```toml
[WebServer]
SessionTimeout = '24h'
```

## Fixed example

```toml
[WebServer]
SessionTimeout = '15m'
```

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/CONFIG.md#sessiontimeout
