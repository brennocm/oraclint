# NS-WEB-003: Wildcard CORS origin

| Severity | Target | Status | CWE |
|---|---|---|---|
| medium | config | stable | CWE-942 |

## Description

Fires when any comma-separated entry of `WebServer.AllowOrigins` is `*`
(default `http://localhost:3000,http://localhost:6688`).

## Why it matters

The node passes the entries to gin-contrib/cors (v1.7.2), which switches to
"allow all origins" as soon as one entry is `*` and answers every origin with
`Access-Control-Allow-Origin: *`. Browsers do not expose credentialed
responses for a wildcard origin, which limits the damage, but any website a
node operator visits can still send requests to the node API and read
unauthenticated responses. The node documentation recommends setting explicit
origins "for security reasons".

## Vulnerable example

```toml
[WebServer]
AllowOrigins = '*'
```

## Fixed example

```toml
[WebServer]
AllowOrigins = 'https://node.example.com'
```

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/CONFIG.md#alloworigins
- https://github.com/gin-contrib/cors/blob/v1.7.2/config.go
