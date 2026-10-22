# NS-WEB-006: LDAP authentication without TLS

| Severity | Target | Status | CWE |
|---|---|---|---|
| high | config | stable | CWE-319, CWE-523 |

## Description

Fires when `WebServer.AuthenticationMethod = 'ldap'` and
`WebServer.LDAP.ServerTLS = false` (default `true`).

## Why it matters

With LDAP authentication, the node forwards every operator's username and
password to the directory server and binds with a read-only service account.
Without `ldaps://`, all of these credentials cross the network in cleartext,
and they are usually corporate credentials valid far beyond the node.

## Vulnerable example

```toml
[WebServer]
AuthenticationMethod = 'ldap'

[WebServer.LDAP]
ServerTLS = false
```

## Fixed example

```toml
[WebServer]
AuthenticationMethod = 'ldap'

[WebServer.LDAP]
ServerTLS = true
```

with `ServerAddress = 'ldaps://...'` in `secrets.toml`.

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/CONFIG.md#webserverldap
