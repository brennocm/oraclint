# NS-RPC-003: Single primary RPC node for chain

| Severity | Target | Status | CWE |
|---|---|---|---|
| low | config | stable | CWE-1357 |

## Description

Fires for each enabled `[[EVM]]` chain (`Enabled` defaults to `true`) that has
exactly one primary node (`SendOnly` not `true`), when that node is not marked
`IsLoadBalancedRPC = true`.

## Why it matters

An oracle node is only as available and as honest as its view of the chain.
With a single primary RPC endpoint, an outage at that provider stops the node
on that chain, and stale or manipulated responses cannot be noticed by
comparing with another source. The node security best practices recommend
redundant, load-balanced RPC connectivity. With a single non-load-balanced
node, the node also marks it alive even when it is out of sync
(`IsLoadBalancedRPC` docs).

## Vulnerable example

```toml
[[EVM]]
ChainID = '1'

[[EVM.Nodes]]
Name = 'only'
HTTPURL = 'https://rpc-a.example.com'
```

## Fixed example

```toml
[[EVM.Nodes]]
Name = 'provider-a'
HTTPURL = 'https://rpc-a.example.com'

[[EVM.Nodes]]
Name = 'provider-b'
HTTPURL = 'https://rpc-b.example.net'
```

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/CONFIG.md#evmnodes
- https://docs.chain.link/chainlink-nodes/resources/best-security-practices
