# oraclint

[![CI](https://github.com/brennocm/oraclint/actions/workflows/ci.yml/badge.svg)](https://github.com/brennocm/oraclint/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/brennocm/oraclint)](https://goreportcard.com/report/github.com/brennocm/oraclint)
[![Release](https://img.shields.io/github/v/release/brennocm/oraclint)](https://github.com/brennocm/oraclint/releases)
[![License](https://img.shields.io/github/license/brennocm/oraclint)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/brennocm/oraclint/badge)](https://scorecard.dev/viewer/?uri=github.com/brennocm/oraclint)

**Static security linter for Chainlink node deployments.** oraclint reads a
node's `config.toml` and `secrets.toml`, plus the docker-compose files,
Kubernetes manifests and `.env` files around it, and reports insecure settings
with their exact location, why they matter and how to fix them. It runs fully
offline and never touches a running node.

![oraclint demo](docs/assets/demo.gif)

## Why

Chainlink node operators run infrastructure that signs transactions and
reports data that smart contracts holding real value depend on. Many of the
ways such a node gets compromised are not exploits but configuration: an
operator UI published to the internet, a database reached without TLS, a
keystore password of eight characters, an RPC key committed in plain sight, a
development flag left on.

These mistakes are easy to make and easy to catch before deployment, the same
way `tfsec`, `checkov` or `kube-bench` catch them for Terraform and Kubernetes.
oraclint brings that to Chainlink nodes, with every rule verified against the
node's own source code and documentation.

## Features

- **35 rules** across node config, secrets, file permissions, docker-compose,
  Kubernetes and dotenv files, each verified against node **v2.69.0** and
  documented with the vulnerable pattern, the fix and references.
- **Default-aware:** a missing key is evaluated with the node's actual default;
  multiple config files are merged with the node's override semantics.
- **Exact locations** (`file:line:column`) for every finding.
- **Never prints secrets:** two layers of redaction, enforced by a fuzz test
  across every output format.
- **Text, JSON and SARIF 2.1.0** output; SARIF plugs into GitHub code scanning.
- **Suppressions with mandatory justification**, inline or in `.oraclint.yaml`,
  that stay visible in JSON and SARIF.
- **Small and offline:** three direct runtime dependencies (cobra, go-toml, yaml),
  no network access, hostile-input tested (alias bombs, deep nesting, binary
  files, symlinks escaping the scan root).

## Install

**Release binaries** (Linux, macOS, Windows; amd64 and arm64) are on the
[releases page](https://github.com/brennocm/oraclint/releases), with checksums,
signatures, SBOMs and build provenance (see [Verifying a release](#verifying-a-release)).

**Go:**

```sh
go install github.com/brennocm/oraclint/cmd/oraclint@latest
```

**Docker** (the image runs as a non-root user; `--user` lets it read files
that are only readable by you, such as a `0600` secrets file):

```sh
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src:ro" -w /src ghcr.io/brennocm/oraclint:latest scan .
```

## Quick start

```sh
oraclint scan .                          # scan the current directory
oraclint rules list                      # see every rule
oraclint rules explain NS-RPC-001        # read the docs for one rule
```

## Usage

```text
oraclint scan [paths...] [flags]

  -f, --format string        text, json or sarif (default "text")
  -o, --output string        write the report to a file (mode 0600)
      --min-severity string  hide findings below this severity (default "info")
      --fail-on string       exit 1 if a finding has at least this severity, or "none" (default "low")
      --enable strings       rule IDs to run even if experimental
      --disable strings      rule IDs not to run
      --experimental         also run experimental rules
      --config-file string   oraclint configuration (default ./.oraclint.yaml if present)
      --ignore-suppressions  ignore .oraclint.yaml and inline directives (audit mode)
      --no-color             disable colors (NO_COLOR is honored too)
  -q, --quiet                print findings only
  -v, --verbose              debug logging to stderr

      --config file          node config file; repeat to merge several, like the node
      --secrets file         treat file as secrets.toml
      --compose file         treat file as a docker-compose file
      --k8s file             treat file as Kubernetes manifests
      --env file             treat file as a dotenv file
```

Without explicit kinds, oraclint discovers files by name and content:
`config.toml`, `*secret*.toml` and other node TOML files, `docker-compose*.yml`
and `compose*.yaml`, YAML files with `apiVersion` and `kind`, and `.env` files.
`.git/` and `node_modules/` are skipped, files over 5 MiB are reported instead
of read, and symlinks that leave the scan root are never followed.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No active finding at or above `--fail-on` |
| `1` | At least one active finding at or above `--fail-on` |
| `2` | Usage or runtime error |

Files that cannot be parsed produce a `parse-error` finding (severity high), so
a broken node file fails the build instead of passing silently.

### Suppressions

Every suppression needs a reason. Inline, on the finding's line or the line
above:

```toml
[WebServer.TLS]
# oraclint:ignore NS-WEB-001 reason="TLS is terminated at the load balancer"
HTTPSPort = 0
```

Or in `.oraclint.yaml`:

```yaml
disable:
  - rule: NS-LOG-001
    reason: "debug logging is required on this lab node"
ignore:
  - rule: NS-WEB-001
    paths: ["deploy/staging/**"]
    reason: "TLS is terminated at the staging load balancer"
```

A directive without a reason (or with an unknown rule ID) is not applied and is
reported as an `invalid-suppression` info finding. Rules disabled by the config
file are listed in every output format.

**Scanning untrusted content** (for example pull requests from forks): the
content can carry its own `.oraclint.yaml` and directives. Use
`--ignore-suppressions` (Action input `ignore-suppressions: "true"`) so only
your own policy applies. Suppressed findings are
counted in the text summary and kept, marked, in JSON (`suppression`) and SARIF
(`suppressions[]`), so GitHub closes the alert with the justification attached.

The JSON format is documented in [docs/output-json.md](docs/output-json.md).

## GitHub Action

```yaml
name: oraclint
on: [push, pull_request]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # upload SARIF to code scanning
    steps:
      - uses: actions/checkout@v7
      - uses: brennocm/oraclint@v0.1.0   # pin to a commit SHA in production
        with:
          path: .
          format: sarif
          output: oraclint.sarif
          fail-on: high
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: oraclint.sarif
```

Inputs: `path`, `format`, `output`, `fail-on`, `min-severity`, `experimental`,
`ignore-suppressions` (set it to `"true"` for pull requests from forks).
See [action.yml](action.yml).

## Rules

Experimental rules are off by default (`--experimental` or `--enable <ID>`).
Run `oraclint rules explain <ID>` for the full documentation of any rule.

<!-- rules:start (generated by `make golden-update`, do not edit) -->
| ID | Severity | Target | Status | Title |
|---|---|---|---|---|
| [NS-AUD-001](docs/rules/NS-AUD-001.md) | low | config | stable | Audit logs forwarded over plaintext |
| [NS-DB-001](docs/rules/NS-DB-001.md) | medium | config | stable | SQL query logging enabled |
| [NS-DB-002](docs/rules/NS-DB-002.md) | high | secrets | stable | Postgres connection to remote host without TLS |
| [NS-DB-003](docs/rules/NS-DB-003.md) | low | secrets | experimental | Postgres TLS does not verify the server |
| [NS-DB-004](docs/rules/NS-DB-004.md) | medium | secrets, env, compose, k8s | stable | Simple database passwords allowed |
| [NS-DKR-001](docs/rules/NS-DKR-001.md) | high | compose | stable | Operator UI port published on a public interface |
| [NS-DKR-002](docs/rules/NS-DKR-002.md) | medium | compose | stable | Postgres port published to the host network |
| [NS-DKR-003](docs/rules/NS-DKR-003.md) | high | compose | stable | Privileged container or host namespace |
| [NS-DKR-004](docs/rules/NS-DKR-004.md) | medium | compose | stable | Node container runs as root |
| [NS-ENV-001](docs/rules/NS-ENV-001.md) | medium | env | stable | Node secrets in a dotenv file |
| [NS-ENV-002](docs/rules/NS-ENV-002.md) | high | compose, k8s | stable | Node secret as literal environment value |
| [NS-FS-001](docs/rules/NS-FS-001.md) | medium | secrets | stable | Secrets file accessible by group or others |
| [NS-IMG-001](docs/rules/NS-IMG-001.md) | medium | compose, k8s | stable | Container image not pinned |
| [NS-INS-001](docs/rules/NS-INS-001.md) | high | config | stable | Development-only [Insecure] flag enabled |
| [NS-K8S-001](docs/rules/NS-K8S-001.md) | high | k8s | stable | Privileged pod or host namespace |
| [NS-K8S-002](docs/rules/NS-K8S-002.md) | medium | k8s | stable | Container securityContext not hardened |
| [NS-K8S-004](docs/rules/NS-K8S-004.md) | high | k8s | stable | Operator UI exposed by a Kubernetes Service |
| [NS-KS-001](docs/rules/NS-KS-001.md) | high | config | stable | Keystore encrypted with insecure fast scrypt parameters |
| [NS-KS-002](docs/rules/NS-KS-002.md) | high | secrets, env, compose, k8s | stable | Weak keystore password |
| [NS-LOG-001](docs/rules/NS-LOG-001.md) | low | config | stable | Debug log level |
| [NS-MET-001](docs/rules/NS-MET-001.md) | low | secrets | experimental | Prometheus metrics endpoint without authentication |
| [NS-RPC-001](docs/rules/NS-RPC-001.md) | high | config | stable | RPC endpoint uses unencrypted transport |
| [NS-RPC-002](docs/rules/NS-RPC-002.md) | medium | config | stable | Credential embedded in RPC URL |
| [NS-RPC-003](docs/rules/NS-RPC-003.md) | low | config | stable | Single primary RPC node for chain |
| [NS-SEC-001](docs/rules/NS-SEC-001.md) | high | config | stable | Secret setting in config file |
| [NS-SEC-002](docs/rules/NS-SEC-002.md) | medium | config | stable | Credential in AuditLogger headers |
| [NS-TEL-001](docs/rules/NS-TEL-001.md) | medium | config | stable | Telemetry over an insecure connection |
| [NS-TRC-001](docs/rules/NS-TRC-001.md) | medium | config | stable | Traces exported unencrypted to a remote collector |
| [NS-WEB-001](docs/rules/NS-WEB-001.md) | medium | config | stable | Operator UI served without HTTPS |
| [NS-WEB-002](docs/rules/NS-WEB-002.md) | medium | config | stable | Session cookies without the Secure flag |
| [NS-WEB-003](docs/rules/NS-WEB-003.md) | medium | config | stable | Wildcard CORS origin |
| [NS-WEB-004](docs/rules/NS-WEB-004.md) | low | config | stable | HTTP not redirected to HTTPS |
| [NS-WEB-005](docs/rules/NS-WEB-005.md) | low | config | stable | Long idle session timeout |
| [NS-WEB-006](docs/rules/NS-WEB-006.md) | high | config | stable | LDAP authentication without TLS |
| [NS-WEB-007](docs/rules/NS-WEB-007.md) | low | config | experimental | Login rate limit relaxed |
<!-- rules:end -->

### Rules considered and left out

While building the catalog, these candidates were investigated and
deliberately not shipped:

- **Database password complexity:** the node already refuses weak database
  passwords at startup.
- **`InsecurePPROFHeap`:** deprecated, has no effect in v2.69.0.
- **pprof endpoints:** always behind authentication in the node's router.
- **Plaintext listener bound to `0.0.0.0`:** the node default, and required
  inside containers for port publishing; exposure is checked where it
  actually happens (NS-DKR-001, NS-K8S-004).
- **Missing `user:` in compose:** official production images already run as UID
  14933; only an explicit root user is flagged (NS-DKR-004).
- **WebAuthn MFA not configured (planned NS-WEB-008):** MFA is enrolled per user
  account in the operator UI; the configuration only sets the relying-party
  ID, so a static scan cannot tell whether accounts use MFA. The finding would
  be mostly noise.
- **No RPC provider diversity (planned NS-RPC-004):** "same provider" can only be
  guessed from DNS names (CNAMEs, white-label endpoints and self-hosted proxies
  defeat it), so the rule would be unreliable. NS-RPC-003 covers the
  single-endpoint case.
- **Writable root filesystem (planned NS-K8S-003):** merged into NS-K8S-002 so a
  container yields one securityContext finding instead of three.

Rule IDs are never reused, which is why some numbers are missing.

## Design

oraclint is a pipeline of small packages: `loader` finds and classifies files
and parses them into a position-aware `model` (every value knows its
`file:line:column`, and absent keys resolve to the node's documented defaults);
the `engine` runs each `rules.Rule` (a two-method interface, one rule per
file) on the targets it applies to, applies `suppress`ions, passes every
message through `redact`, and sorts the findings deterministically; `report`
renders text, JSON or SARIF. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
and the [decision records](docs/adr/).

On the example deployment (5 files, 35 rules) a full scan takes about 4 ms
(`go test -bench BenchmarkScan ./internal/engine`, Intel i5-1135G7).

## Security

- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): what oraclint protects, from
  whom, and how (including the "never print a secret" invariant).
- [SECURITY.md](SECURITY.md): how to report a vulnerability in oraclint.

### Verifying a release

The checksum file is signed keylessly with cosign (Sigstore bundle), container
images are signed by digest, and every archive has a GitHub build provenance
attestation. Download the archive, `checksums.txt` and
`checksums.txt.sigstore.json` from the release, then:

```sh
# 1. The checksum file was signed by this repository's release workflow
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/brennocm/oraclint/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# 2. The archive matches the signed checksums
sha256sum --ignore-missing -c checksums.txt

# 3. The archive was built by GitHub Actions from this repository
gh attestation verify oraclint_Linux_x86_64.tar.gz --repo brennocm/oraclint

# Container image signature
cosign verify ghcr.io/brennocm/oraclint:v0.1.0 \
  --certificate-identity-regexp '^https://github.com/brennocm/oraclint/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Each archive also ships with an SPDX SBOM (`*.sbom.json`) generated by syft.

## Limitations

- **Static analysis only.** oraclint sees files, not the running node. It
  cannot detect a compromise, configuration injected at runtime (for example
  `CL_CONFIG` or secrets supplied only as environment variables outside the
  scanned files), or what is actually reachable on the network.
- **Verified against node v2.69.0.** Older or newer node versions may have
  different keys and defaults; findings can be wrong for them.
- **Heuristics where the node leaves no choice:** hosts on private networks are
  not flagged by plaintext-transport rules; RPC keys in URL paths are recognized
  by shape (20+ characters with a digit); compose node services are recognized
  by image or service name containing `chainlink`; default ports 6688/6689 are
  assumed for exposure rules.
- **Not modeled in v1:** Helm charts (render them with `helm template` first),
  compose `env_file:` references, non-EVM chain sections, merging of config
  files discovered in a directory (pass them with repeated `--config`).
- **Windows:** the file permission rule (NS-FS-001) does not run.

## Disclaimer

oraclint is an independent project and is **not affiliated with, endorsed by or
sponsored by Chainlink Labs**. "Chainlink" is used only to describe the software
this tool analyzes. Findings are guidance, not a security audit.

## License

[Apache-2.0](LICENSE)
