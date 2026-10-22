# NS-DKR-002: Postgres port published to the host network

| Severity | Target | Status | CWE |
|---|---|---|---|
| medium | compose | stable | CWE-668 |

## Description

Fires for a compose service running Postgres (image name `postgres*`,
`postgis` or `timescaledb`) that publishes container port `5432` on anything
other than a loopback address.

## Why it matters

The node reaches its database over the compose network and needs no published
port. Publishing it makes the database, which holds the node's encrypted keys
and all its state, reachable from outside the host and open to password
guessing. The official Docker guide publishes `5432:5432` for a local test
setup and notes that this makes the database accessible outside Docker.

## Vulnerable example

```yaml
services:
  postgres:
    image: postgres:16
    ports:
      - "5432:5432"
```

## Fixed example

```yaml
services:
  postgres:
    image: postgres:16
    # no ports: the node connects to postgres:5432 on the compose network
```

## References

- https://docs.chain.link/chainlink-nodes/v1/running-a-chainlink-node
- https://docs.chain.link/chainlink-nodes/resources/best-security-practices
