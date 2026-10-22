# NS-ENV-001: Node secrets in a dotenv file

| Severity | Target | Status | CWE |
|---|---|---|---|
| medium | env | stable | CWE-312, CWE-538 |

## Description

Fires for every non-empty node secret variable in a dotenv file (`.env`,
`.env.*`, `*.env`) inside the scanned tree: `CL_DATABASE_URL`,
`CL_DATABASE_BACKUP_URL`, `CL_PASSWORD_KEYSTORE`, `CL_PASSWORD_VRF`,
`CL_PYROSCOPE_AUTH_TOKEN`, `CL_PROMETHEUS_AUTH_TOKEN`, `CL_THRESHOLD_KEY_SHARE`
and `POSTGRES_PASSWORD`.

Template files ending in `.example`, `.sample`, `.template`, `.dist` or `.tmpl`
are not scanned by default.

## Why it matters

Docker Compose reads `.env` automatically, so it is a convenient place for
the node's secrets, and an easy file to commit or include in an image build
context by accident. If it lives in the repository directory, one `git add .`
publishes the keystore password.

## Vulnerable example

```sh
# .env in the repository
CL_PASSWORD_KEYSTORE=...
```

## Fixed example

Keep the file outside the repository (or at least in `.gitignore` and
`.dockerignore`), or use Docker secrets / Kubernetes Secrets.

## References

- https://github.com/smartcontractkit/chainlink/blob/v2.69.0/docs/SECRETS.md
- https://docs.docker.com/compose/how-tos/use-secrets/
