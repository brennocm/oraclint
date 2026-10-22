# hardened-node

A Chainlink node deployment that passes every oraclint rule, including the
experimental ones. Use it as a reference, not as a drop-in configuration:
replace the example hosts, and keep the real `secrets.toml` out of version
control with mode `0600` (the copy here holds placeholders only).

```sh
chmod 600 examples/hardened-node/secrets.toml
oraclint scan --experimental examples/hardened-node
```
