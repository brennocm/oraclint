# NS-DB-004: Simple database passwords allowed

| Severity | Target | Status | CWE |
|---|---|---|---|
| medium | secrets, env, compose, k8s | stable | CWE-521 |

## Description

Fires when `Database.AllowSimplePasswords = true` in `secrets.toml` (default
`false`), or when `CL_DATABASE_ALLOW_SIMPLE_PASSWORDS` is set to `true`
(case-insensitive, as the node reads it) in a dotenv file, a compose service or
a Kubernetes container.

## Why it matters

The node normally refuses database URLs whose password is shorter than 16
characters or has surrounding whitespace. This setting skips that check. The
node rejects it on production builds (`DatabaseSecrets.validateConfig`), so the
rule is an **early warning**: it catches the setting before a deployment fails,
and before a weak database password reaches a non-production build that is
exposed anyway.

## Vulnerable example

```toml
[Database]
AllowSimplePasswords = true
```

## Fixed example

```toml
[Database]
# AllowSimplePasswords removed; database password of 16+ random characters
```

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/SECRETS.md#allowsimplepasswords
- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/core/config/toml/types.go
