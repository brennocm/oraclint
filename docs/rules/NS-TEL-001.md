# NS-TEL-001: Telemetry over an insecure connection

| Severity | Target | Status | CWE |
|---|---|---|---|
| medium | config | stable | CWE-319 |

## Description

Fires when:

- `Telemetry.Enabled = true` and `Telemetry.InsecureConnection = true` (default
  `false`) with a non-internal `Telemetry.Endpoint`; or
- `Telemetry.ChipIngressInsecureConnection = true` (default `false`) with a
  non-internal `Telemetry.ChipIngressEndpoint`. This applies even when
  `Telemetry.Enabled` is false: the node's durable emitter
  (`DurableEmitterEnabled`, default `true`) sends CHIP ingress events on its
  own (`core/services/chainlink/application.go`, v2.69.0).

## Why it matters

Telemetry and CHIP ingress events carry operational data about the node and
the jobs it runs. The documentation says `InsecureConnection` is "only
available in dev mode", but the node does not enforce this in v2.69.0
(`Telemetry.ValidateConfig` only skips the `CACertFile` requirement).

## Vulnerable example

```toml
[Telemetry]
Enabled = true
Endpoint = 'telemetry.example.com:4317'
InsecureConnection = true
```

## Fixed example

```toml
[Telemetry]
Enabled = true
Endpoint = 'telemetry.example.com:4317'
CACertFile = '/certs/telemetry-ca.pem'
```

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/CONFIG.md#telemetry
- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/core/config/toml/types.go
