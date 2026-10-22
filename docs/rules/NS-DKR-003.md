# NS-DKR-003: Privileged container or host namespace

| Severity | Target | Status | CWE |
|---|---|---|---|
| high | compose | stable | CWE-250 |

## Description

Fires for any compose service with `privileged: true`, `network_mode: host`,
`pid: host`, or `cap_add` containing `ALL`, `SYS_ADMIN`, `NET_ADMIN`,
`SYS_PTRACE`, `SYS_MODULE` or `DAC_READ_SEARCH` (with or without the `CAP_`
prefix).

## Why it matters

These settings remove the isolation between the container and the host. A
bug in the node, an external adapter or any other service with them becomes a
host compromise, and from there access to every key and secret on the
machine. The node needs none of them.

## Vulnerable example

```yaml
services:
  chainlink:
    image: smartcontract/chainlink:2.69.0
    privileged: true
    network_mode: host
```

## Fixed example

```yaml
services:
  chainlink:
    image: smartcontract/chainlink:2.69.0
    cap_drop: [ALL]
```

## References

- https://docs.docker.com/reference/compose-file/services/
- https://docs.docker.com/engine/security/
