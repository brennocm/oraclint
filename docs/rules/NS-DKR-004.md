# NS-DKR-004: Node container runs as root

| Severity | Target | Status | CWE |
|---|---|---|---|
| medium | compose | stable | CWE-250 |

## Description

Fires when a node service sets `user:` to `root` or UID `0` (with or without a
group). A service without `user:` is not flagged: official production images
already run as UID:GID `14933:14933` (`core/chainlink.Dockerfile`, v2.69.0).

## Why it matters

Running as root inside the container gives a compromised node process more
power to escape the container and to read or change mounted host files. The
usual reason for `user: root` is a permission error on a bind mount; the node
documentation explains how to align the mount with UID 14933 instead.

## Vulnerable example

```yaml
services:
  chainlink:
    image: smartcontract/chainlink:2.69.0
    user: root
```

## Fixed example

```yaml
services:
  chainlink:
    image: smartcontract/chainlink:2.69.0
    # no user override; chown the data directory to 14933:14933
```

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/core/chainlink.Dockerfile
- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/CONFIG.md#rootdir
