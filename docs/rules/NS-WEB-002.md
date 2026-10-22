# NS-WEB-002: Session cookies without the Secure flag

| Severity | Target | Status | CWE |
|---|---|---|---|
| medium | config | stable | CWE-614 |

## Description

Fires when `WebServer.SecureCookies = false` (default `true`).

## Why it matters

Without the `Secure` attribute, the browser also sends the operator session
cookie over plaintext HTTP. Anyone able to observe that traffic can replay the
cookie and act as the operator until the session expires. The node docs
describe this setting as a way to "enable standard HTTP requests", i.e. a
development convenience.

## Vulnerable example

```toml
[WebServer]
SecureCookies = false
```

## Fixed example

```toml
[WebServer]
# SecureCookies removed (defaults to true); access the UI over HTTPS
```

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/CONFIG.md#securecookies
