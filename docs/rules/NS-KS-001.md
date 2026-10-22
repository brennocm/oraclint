# NS-KS-001: Keystore encrypted with insecure fast scrypt parameters

| Severity | Target | Status | CWE |
|---|---|---|---|
| high | config | stable | CWE-916 |

## Description

Fires when `InsecureFastScrypt = true` is set in `config.toml` (default: `false`).

## Why it matters

The node encrypts its private keys (EVM transmitter keys, OCR and P2P keys) with
a password-derived key using scrypt. `InsecureFastScrypt` replaces the scrypt
parameters with cheap ones meant for tests. Anyone who obtains the database or a
key export can then brute-force the keystore password orders of magnitude
faster.

The node documentation says "DO NOT ENABLE THIS IN PRODUCTION", but unlike the
`[Insecure]` section the setting is **not** rejected by production builds
(verified in v2.69.0), so nothing stops it from reaching a live node.

## Vulnerable example

```toml
InsecureFastScrypt = true
```

## Fixed example

```toml
# InsecureFastScrypt removed (defaults to false)
```

Keys created while the setting was enabled were encrypted with weak parameters;
rotate them.

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/CONFIG.md#insecurefastscrypt
