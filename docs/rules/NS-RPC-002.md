# NS-RPC-002: Credential embedded in RPC URL

| Severity | Target | Status | CWE |
|---|---|---|---|
| medium | config | stable | CWE-798, CWE-312 |

## Description

Fires for every `HTTPURL`, `WSURL` or `HTTPURLExtraWrite` of an `[[EVM.Nodes]]`
entry (enabled or not) that carries:

- user info (`https://user:password@host`);
- a query parameter named like a credential (`key`, `apikey`, `token`,
  `secret`, `auth`, `signature`, ...); or
- a path segment that looks like an API key: at least 20 characters of
  letters, digits, `-` or `_`, including a digit. This matches the formats of
  common providers such as Infura (`/v3/<key>`), Alchemy (`/v2/<key>`) and
  QuickNode (`/<token>/`).

## Why it matters

RPC provider keys are billable credentials and, when unrestricted, let anyone
use the quota or impersonate the node's traffic. The node has no secrets field
for RPC URLs, so they live in config files, which are usually committed,
copied into tickets and shared with other teams.

## Vulnerable example

```toml
[[EVM.Nodes]]
Name = 'infura'
HTTPURL = 'https://mainnet.infura.io/v3/<key>'
```

## Fixed example

Move the `[[EVM]]` sections with keys to a separate config file that is not
committed (the node merges multiple `-config` files in order), or inject them
with the `CL_CONFIG` environment variable from a secret manager; the node
applies `CL_CONFIG` last. Restrict keys at the provider to the node's IP
addresses. Rotate any key that was committed.

## Limitations

Keys shorter than 20 characters in the URL path are not recognized.

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/CONFIG.md#evmnodes
