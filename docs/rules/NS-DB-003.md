# NS-DB-003: Postgres TLS does not verify the server

| Severity | Target | Status | CWE |
|---|---|---|---|
| low | secrets | experimental | CWE-295 |

## Description

Fires when `Database.URL` or `Database.BackupURL` points to a non-internal host
and:

- `sslmode` is absent or `prefer`: TLS is attempted but the client silently
  falls back to plaintext (the Go Postgres driver defaults to `prefer`); or
- `sslmode=require` without `sslrootcert`: traffic is encrypted but the server
  certificate is not verified.

Experimental (disabled by default; enable with `--experimental` or
`--enable NS-DB-003`): many managed databases are reached this way inside
networks the operator trusts, so the finding can be noisy.

## Why it matters

Without certificate verification, an attacker who can intercept traffic
between the node and the database can impersonate the database, capture the
password and read or modify node state.

## Vulnerable example

```toml
[Database]
URL = 'postgresql://chainlink:...@db.example.com:5432/chainlink'
```

## Fixed example

```toml
[Database]
URL = 'postgresql://chainlink:...@db.example.com:5432/chainlink?sslmode=verify-full&sslrootcert=/certs/db-ca.pem'
```

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/SECRETS.md#database
- https://www.postgresql.org/docs/current/libpq-ssl.html
