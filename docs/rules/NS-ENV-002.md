# NS-ENV-002: Node secret as literal environment value

| Severity | Target | Status | CWE |
|---|---|---|---|
| high | compose, k8s | stable | CWE-798, CWE-312 |

## Description

Fires when a node secret variable (see NS-ENV-001 for the list) is given a
literal value:

- in compose `environment:` (map or list syntax), unless the value uses
  `${VAR}`/`$VAR` interpolation or is passed through from the host (`- VAR`);
- in a Kubernetes container `env:` entry with `value:` instead of
  `valueFrom.secretKeyRef`.

## Why it matters

Compose files and manifests are committed, reviewed in pull requests and
copied between environments. A literal secret in them is readable by everyone
with repository access, and it also appears in `docker inspect`,
`kubectl get -o yaml` and CI logs.

## Vulnerable example

```yaml
environment:
  CL_PASSWORD_KEYSTORE: my-keystore-password
```

## Fixed example

```yaml
# compose
environment:
  CL_PASSWORD_KEYSTORE: ${CL_PASSWORD_KEYSTORE}

# kubernetes
env:
  - name: CL_PASSWORD_KEYSTORE
    valueFrom:
      secretKeyRef: {name: chainlink-secrets, key: keystore-password}
```

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/SECRETS.md
- https://docs.docker.com/compose/how-tos/use-secrets/
- https://kubernetes.io/docs/concepts/configuration/secret/
