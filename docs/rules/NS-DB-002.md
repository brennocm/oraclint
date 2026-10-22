# NS-DB-002: Postgres connection to remote host without TLS

| Severity | Target | Status | CWE |
|---|---|---|---|
| high | secrets | stable | CWE-319 |

## Description

Fires when `Database.URL` or `Database.BackupURL` in `secrets.toml` points to a
host on a public network with `sslmode=disable` or `sslmode=allow`.

Unix sockets (`?host=/var/run/postgresql`) and internal hosts (see NS-RPC-001)
are not flagged.

## Why it matters

The node database stores encrypted keys, job specs, pending transactions and
bridge credentials. The connection also carries the database password. With
`disable` nothing is encrypted; with `allow` the client only uses TLS if the
server insists, so an active attacker can downgrade it. The official guide uses
`sslmode=disable` for local testing only and says never to do this on a
production node.

## Vulnerable example

```toml
[Database]
URL = 'postgresql://chainlink:...@db.example.com:5432/chainlink?sslmode=disable'
```

## Fixed example

```toml
[Database]
URL = 'postgresql://chainlink:...@db.example.com:5432/chainlink?sslmode=verify-full&sslrootcert=/certs/ca.pem'
```

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/SECRETS.md#database
- https://docs.chain.link/chainlink-nodes/v1/running-a-chainlink-node
- https://www.postgresql.org/docs/current/libpq-ssl.html
