# NS-WEB-007: Login rate limit relaxed

| Severity | Target | Status | CWE |
|---|---|---|---|
| low | config | experimental | CWE-307 |

## Description

Fires when `WebServer.RateLimit.Unauthenticated` and
`WebServer.RateLimit.UnauthenticatedPeriod` (defaults `5` per `20s`, i.e.
15 per minute) are set so that more than 30 unauthenticated requests per minute
are allowed.

Experimental (disabled by default; enable with `--experimental` or
`--enable NS-WEB-007`): the right limit depends on how many people and tools
reach the node, so the threshold is a judgment call.

## Why it matters

The unauthenticated limit is what throttles password guessing against the
operator login. Relaxing it makes online brute-force attacks faster.

## Vulnerable example

```toml
[WebServer.RateLimit]
Unauthenticated = 100
UnauthenticatedPeriod = '1m'
```

## Fixed example

```toml
[WebServer.RateLimit]
Unauthenticated = 5
UnauthenticatedPeriod = '20s'
```

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/CONFIG.md#webserverratelimit
