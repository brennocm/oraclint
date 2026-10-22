# NS-SEC-001: Secret setting in config file

| Severity | Target | Status | CWE |
|---|---|---|---|
| high | config | stable | CWE-260, CWE-312 |

## Description

Fires when a key that belongs to the secrets schema appears in a config file:
`Database.URL`, `Database.BackupURL`, `Password.Keystore`, `Password.VRF`,
`WebServer.LDAP.ReadOnlyUserPass`, `WebServer.OIDC.clientSecret`,
`Prometheus.AuthToken`, `Pyroscope.AuthToken`, `Mercury.Credentials`,
`Threshold.ThresholdKeyShare`, `CRE.Streams.ApiKey`, `CRE.Streams.ApiSecret`,
`CRE.LocalSecretOverrides`, `P2PKey`, `DKGRecipientKey`.

## Why it matters

The node keeps configuration and secrets in separate files so the
configuration can be versioned and shared while secrets stay in a secret store.
A credential in `config.toml` tends to end up in Git history, CI logs and
support tickets.

The node decodes config files strictly and **refuses to start** with these
keys, so this rule is an early warning: by the time the node complains, the
secret may already be committed. Treat it as exposed and rotate it.

## Vulnerable example

```toml
# config.toml
[Password]
Keystore = '...'
```

## Fixed example

```toml
# secrets.toml (not committed, mode 0600)
[Password]
Keystore = '...'
```

or set `CL_PASSWORD_KEYSTORE` from a secret manager.

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/SECRETS.md
- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/CONFIG.md
