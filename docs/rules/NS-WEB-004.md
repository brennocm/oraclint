# NS-WEB-004: HTTP not redirected to HTTPS

| Severity | Target | Status | CWE |
|---|---|---|---|
| low | config | stable | CWE-319 |

## Description

Fires when TLS is explicitly configured (`WebServer.TLS.CertPath`, `KeyPath`
or `HTTPSPort` set, and HTTPS not disabled), the plaintext listener is enabled
(`WebServer.HTTPPort`, default `6688`) and `WebServer.TLS.ForceRedirect` is not
`true` (default `false`).

## Why it matters

Having HTTPS available does not help if operators still reach the plaintext
port: an old bookmark or a typed `http://` URL results in a cleartext login.
`ForceRedirect` makes the node redirect those requests to HTTPS. Alternatively
disable the plaintext listener entirely.

## Vulnerable example

```toml
[WebServer.TLS]
CertPath = '/chainlink/tls/server.crt'
KeyPath = '/chainlink/tls/server.key'
```

## Fixed example

```toml
[WebServer.TLS]
CertPath = '/chainlink/tls/server.crt'
KeyPath = '/chainlink/tls/server.key'
ForceRedirect = true
```

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/CONFIG.md#forceredirect
