# NS-MET-001: Prometheus metrics endpoint without authentication

| Severity | Target | Status | CWE |
|---|---|---|---|
| low | secrets | experimental | CWE-306 |

## Description

Fires when a scanned `secrets.toml` does not set `Prometheus.AuthToken`.

Experimental (disabled by default; enable with `--experimental` or
`--enable NS-MET-001`): the token can also come from the
`CL_PROMETHEUS_AUTH_TOKEN` environment variable, which a file scan of the
secrets file cannot see.

## Why it matters

The `/metrics` endpoint shares the operator web server port. Without a token
the node serves metrics to anyone who can reach that port
(`core/web/router.go`: the bearer check is skipped when the token is empty).
Metrics reveal the jobs the node runs, chains, balances-related gauges and
software versions, which is useful reconnaissance. Profiling endpoints
(`/debug/pprof`) are always behind authentication.

## Vulnerable example

```toml
# secrets.toml without a [Prometheus] section
[Password]
Keystore = '...'
```

## Fixed example

```toml
[Prometheus]
AuthToken = '<random token>'
```

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/SECRETS.md#prometheus
