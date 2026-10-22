# NS-WEB-001: Operator UI served without HTTPS

| Severity | Target | Status | CWE |
|---|---|---|---|
| medium | config | stable | CWE-319 |

## Description

Fires when `WebServer.TLS.HTTPSPort = 0` (default `6689`) while the plaintext
listener `WebServer.HTTPPort` is enabled (default `6688`).

## Why it matters

The operator UI and API control the node: jobs, bridges, keys and
transactions. With HTTPS disabled, logins, API credentials and session
cookies travel in cleartext between the operator and the node. The node runs
its TLS server only when `HTTPSPort` is non-zero (verified in v2.69.0,
`core/cmd/shell.go`).

If TLS is terminated by a reverse proxy in front of the node and the node port
is not reachable from anywhere else, suppress this finding with that reason.

## Vulnerable example

```toml
[WebServer.TLS]
HTTPSPort = 0
```

## Fixed example

```toml
[WebServer.TLS]
CertPath = '/chainlink/tls/server.crt'
KeyPath = '/chainlink/tls/server.key'
HTTPSPort = 6689
ForceRedirect = true
```

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/CONFIG.md#webservertls
- https://docs.chain.link/chainlink-nodes/resources/best-security-practices
