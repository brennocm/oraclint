# NS-INS-001: Development-only [Insecure] flag enabled

| Severity | Target | Status | CWE |
|---|---|---|---|
| high | config | stable | CWE-489 |

## Description

Fires for each of these set to `true` (all default to `false`):

- `Insecure.DevWebServer`: skips secure web server settings (allowed hosts, SSL).
- `Insecure.OCRDevelopmentMode`: runs OCR in development mode.
- `Insecure.InfiniteDepthQueries`: disables the GraphQL query depth limit.
- `Insecure.DisableRateLimiting`: disables rate limiting.

## Why it matters

These switches remove protections of the operator API and OCR to make local
development easier. Production builds of the node reject them at startup
(`Insecure.ValidateConfig`; `OCRDevelopmentMode` is also accepted by test
builds). This rule is an **early warning**: it catches the setting in CI before a
deployment fails, and before a development build with these settings is
exposed.

## Vulnerable example

```toml
[Insecure]
DevWebServer = true
```

## Fixed example

```toml
# no [Insecure] section in production configuration
```

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/CONFIG.md#insecure
- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/core/config/toml/types.go
