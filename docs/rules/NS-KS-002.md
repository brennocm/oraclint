# NS-KS-002: Weak keystore password

| Severity | Target | Status | CWE |
|---|---|---|---|
| high | secrets, env, compose, k8s | stable | CWE-521 |

## Description

Fires when `Password.Keystore` or `Password.VRF` in `secrets.toml`, or a
literal `CL_PASSWORD_KEYSTORE` / `CL_PASSWORD_VRF` in a dotenv file, compose
service or Kubernetes container, fails the node's own complexity rule: at least
16 characters and no leading or trailing whitespace
(`utils.VerifyPasswordComplexity`).

## Why it matters

The keystore password protects the node's private keys, including the keys
that sign on-chain transactions and OCR reports. The node checks complexity
only when it creates a new, empty keystore; for backwards compatibility it
accepts any password for an existing keystore
(`core/cmd/key_store_authenticator.go`, v2.69.0). A node set up with a weak
password, or set up before the rule existed, keeps running with it.

The finding never shows the password or its length.

## Vulnerable example

```toml
[Password]
Keystore = 'changeme'
```

## Fixed example

```toml
[Password]
Keystore = '<at least 16 random characters>'
```

Change the password of an existing keystore with the node's password change
procedure, not only in this file.

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/SECRETS.md#password
- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/core/utils/password.go
