# NS-IMG-001: Container image not pinned

| Severity | Target | Status | CWE |
|---|---|---|---|
| medium | compose, k8s | stable | CWE-1357, CWE-494 |

## Description

Fires for every compose service image and Kubernetes container or init
container image that has no tag (which means `latest`) or the `latest` tag, and
no `@sha256:` digest. Interpolated references (`${VERSION}`) are skipped.

## Why it matters

Unpinned images change under you: a restart can pull an untested node
release (with new config defaults or database migrations) or a tampered image.
A version tag makes deployments reproducible; a digest also protects against a
tag being moved. The node documentation states that the `latest` tag does not
work for the node image.

## Vulnerable example

```yaml
services:
  chainlink:
    image: smartcontract/chainlink:latest
  postgres:
    image: postgres
```

## Fixed example

```yaml
services:
  chainlink:
    image: smartcontract/chainlink:2.69.0@sha256:<digest>
  postgres:
    image: postgres:16.4
```

## References

- https://docs.chain.link/chainlink-nodes/v1/running-a-chainlink-node
