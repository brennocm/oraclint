# NS-DKR-001: Operator UI port published on a public interface

| Severity | Target | Status | CWE |
|---|---|---|---|
| high | compose | stable | CWE-668 |

## Description

Fires for a compose service running the node (image or service name contains
`chainlink`) that publishes container port `6688` (default `WebServer.HTTPPort`)
or `6689` (default `WebServer.TLS.HTTPSPort`) on anything other than a
loopback address: no host IP (all interfaces), `0.0.0.0`, `::`, or a specific
non-loopback IP. Short (`"6688:6688"`) and long (`target:`/`host_ip:`) port
syntaxes are both understood, including ranges.

## Why it matters

The operator UI and API manage jobs, keys and bridges. The node security best
practices say to keep port 6688 closed to the internet and to reach it through
an SSH tunnel. Docker publishes ports by inserting its own firewall rules, so a
published port is often reachable even when a host firewall such as `ufw` is
configured to block it.

## Vulnerable example

```yaml
services:
  chainlink:
    image: smartcontract/chainlink:2.69.0
    ports:
      - "6688:6688"
```

## Fixed example

```yaml
services:
  chainlink:
    image: smartcontract/chainlink:2.69.0
    ports:
      - "127.0.0.1:6688:6688"   # then: ssh -L 6688:localhost:6688 host
```

## Limitations

The rule uses the default ports. If `WebServer.HTTPPort` is changed, the
published port is not matched.

## References

- https://docs.chain.link/chainlink-nodes/resources/best-security-practices
- https://docs.chain.link/chainlink-nodes/v1/running-a-chainlink-node
