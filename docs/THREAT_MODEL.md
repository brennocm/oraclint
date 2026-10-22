# Threat model

This document covers oraclint itself: a security tool that reads sensitive
files, often in CI, sometimes on content submitted by strangers (pull
requests). It is reviewed whenever input handling, output or the release
process changes.

## Assets

| Asset | Why it matters |
|---|---|
| Secrets inside scanned files | Database URLs with passwords, keystore passwords, RPC keys, tokens. Leaking them through oraclint output (CI logs, SARIF stored by GitHub) would be worse than the misconfiguration it reports. |
| Integrity of results | Users gate deployments on oraclint. A silent false negative is a security failure; a crash or hang is a CI outage. |
| The machine running oraclint | Developer laptops and CI runners hold credentials of their own. |
| The release artifacts | Users run the binary, container image and GitHub Action with access to their repositories. |

## Adversaries

1. **Author of a scanned file**: for example a pull request from a fork, scanned
   in CI. Controls file content, names and symlinks; wants to crash or hang the
   scan, read files outside the repository, hide findings, or exfiltrate CI
   secrets.
2. **Compromised dependency** of oraclint or of its build.
3. **Attacker targeting releases**: replacing a binary, image or Action
   version users download.
4. **Observer of oraclint output**: anyone who can read CI logs or the code
   scanning results, but not the scanned secrets themselves.

## Threats and mitigations (STRIDE)

| Threat | Category | Mitigation |
|---|---|---|
| Secret values echoed in findings, JSON, SARIF or logs | Information disclosure | Rules only reference key names, hosts and identifiers. The engine redacts every message and suppression reason with known secrets collected from all scanned files plus pattern masking (URL credentials, sensitive query parameters, key-like path segments, `password=` text). Parser error messages are reduced to a position. **Invariant enforced by `FuzzNoSecretInOutput`**: random secrets planted in a deployment never appear in any output format, even with a deliberately leaky copy of every rule. Logs contain paths only. See ADR 0007. |
| Parser denial of service (huge files, deep nesting, alias bombs, long lines) | Denial of service | 5 MiB read limit through `io.LimitReader`; go-toml and yaml nesting limits; YAML aliases never expanded and never followed during traversal; bounded line length in dotenv and directive scanning; fuzz targets for every parser; `TestHostileInputs` with a 10 s budget. An alias bomb that hung the scan was found by this test and fixed. |
| Reading files outside the repository via symlinks or `..` | Information disclosure | Directories are read through `os.Root`: the kernel refuses any open that leaves the scan root, without a check-then-open race. Only regular files are opened while walking (no FIFOs or devices). |
| Malicious content hiding findings | Tampering | Suppressions require a written reason and are kept, marked, in JSON and SARIF, so they show up in review; rules disabled and paths excluded by a config file are listed in every output. `--ignore-suppressions` ignores the scanned content's own config and directives (recommended for pull requests from forks). Unknown rule IDs and missing reasons are reported. Unparsable node files produce `parse-error` findings (severity high) instead of being skipped. YAML merge keys are followed and duplicate keys are reported, so values hidden behind anchors or shadowed by a second definition are still checked. |
| Terminal escape injection through scanned values | Tampering / spoofing | Messages, suppression reasons and file names are passed through `redact.Printable`: control characters, invalid UTF-8 bytes (a lone `0x9b` is a CSI on 8-bit terminals) and bidirectional overrides are shown as escapes. JSON and SARIF encoders escape control characters as well. |
| Silent false negatives from wrong rule logic | Tampering (integrity) | Every rule cites the node source/doc it was verified against (pinned version), has positive/negative/default tests and fixtures, and `examples/insecure-node` must trigger every rule on every CI run. |
| Non-deterministic output hiding regressions | Integrity | Findings are sorted by file, line, column, rule and message; golden files pin all output formats byte for byte. |
| Compromised or vulnerable dependency | Elevation of privilege | Three direct runtime dependencies; Dependabot for Go modules and Actions; `govulncheck` in CI; CodeQL and OpenSSF Scorecard workflows. |
| Compromised CI workflow or third-party Action | Elevation of privilege | Every third-party Action is pinned by commit SHA; workflows default to `contents: read` and grant extra permissions per job; checkout without persisted credentials. |
| Tampered release artifacts | Spoofing / tampering | GoReleaser builds in GitHub Actions; checksums signed keylessly with cosign (Sigstore, tied to the workflow identity); SBOMs generated with syft; build provenance attestations via `actions/attest-build-provenance`; distroless non-root container image. Verification steps are in the README. |
| Network exfiltration from the scanner | Information disclosure | oraclint makes no network calls during a scan. `net/http` and `crypto/tls` are not linked into the binary (`go list -deps`); the `net` package is used only to parse IP addresses and host:port strings. |
| Report files readable by other local users | Information disclosure | `--output` files are created with mode `0600`. |

## Residual risks (accepted)

- **Heuristic secret detection.** Redaction can only mask what it recognizes:
  secrets under unusual key names in non-secret files, or keys in URL paths
  shorter than 20 characters, could in theory appear in a message. Rules do not
  put values in messages, so this needs both a rule bug and an unrecognized
  secret.
- **Over-masking.** Values under secret-looking key names are masked
  everywhere they appear in messages, which can make a message less precise.
  Accepted in favor of safety.
- **Line-based directive parsing.** A `#` inside a quoted string can look like
  a comment; such a directive has no valid reason and is reported, never
  applied.
- **A swapped special file during the scan.** A file that is a regular file
  when listed and replaced by a FIFO before it is opened could block the read.
  This requires concurrent write access to the scanned tree.
- **Absolute symlinks inside the repository are not followed** (os.Root
  policy). This is a possible false negative, chosen over the risk of
  following links outside the root.
- **Node version drift.** Rules are verified against node v2.69.0; other
  versions may change keys or defaults. Bumping the target version is an
  explicit task (ADR 0002).
