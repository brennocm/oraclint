# NS-RPC-001: RPC endpoint uses unencrypted transport

| Severity | Target | Status | CWE |
|---|---|---|---|
| high | config | stable | CWE-319 |

## Description

Fires for every `HTTPURL`, `WSURL` or `HTTPURLExtraWrite` of an enabled
`[[EVM]]` chain that uses `http://` or `ws://` to a host on a public network.

Hosts considered internal (not flagged): loopback, private and link-local IP
ranges, single-label names such as Docker Compose or Kubernetes service names
(`geth`), and internal DNS suffixes (`.svc`, `.cluster.local`, `.internal`,
`.local`, `.lan`, `.home.arpa`).

## Why it matters

The node trusts its RPC endpoints for chain state and uses them to broadcast
signed transactions. Over plaintext, anyone on the network path can read the
traffic, including API keys embedded in the URL, and can tamper with responses
(for example fake block heads or logs) to influence what the node observes and
reports.

## Vulnerable example

```toml
[[EVM]]
ChainID = '1'

[[EVM.Nodes]]
Name = 'primary'
WSURL = 'ws://rpc.example.com/ws'
HTTPURL = 'http://rpc.example.com'
```

## Fixed example

```toml
[[EVM.Nodes]]
Name = 'primary'
WSURL = 'wss://rpc.example.com/ws'
HTTPURL = 'https://rpc.example.com'
```

## Limitations

Plaintext traffic inside a private network is not flagged. It is a smaller but
real risk; the node security best practices recommend TLS even behind a VPN.

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/CONFIG.md#evmnodes
- https://docs.chain.link/chainlink-nodes/resources/best-security-practices
