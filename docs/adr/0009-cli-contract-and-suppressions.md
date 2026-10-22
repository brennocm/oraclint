# 9. CLI contract: exit codes, thresholds and suppressions

Date: 2026-10-22

## Status

Accepted

## Context

oraclint mostly runs in CI, where the exit code is the interface. Users also
need a way to accept a finding (for example "TLS is terminated at the load
balancer") without disabling the rule for everyone, and reviewers need to see
those exceptions.

## Decision

**Exit codes**

| Code | Meaning |
|---|---|
| 0 | No active (unsuppressed) finding at or above `--fail-on` |
| 1 | At least one active finding at or above `--fail-on` |
| 2 | Usage or runtime error (bad flag, unknown rule ID, unreadable path, invalid config file) |

`--fail-on` defaults to `low`: any finding except `info` fails the build, which
is the safe default for a security gate; `--fail-on none` reports without
failing. `--min-severity` (default `info`) only controls what is shown, and
hidden findings never fail the build. Parse errors are `high` findings, so an
unreadable node file fails CI instead of passing silently.

**Suppressions**

- Inline: `# oraclint:ignore NS-WEB-001 reason="..."` on the finding's line or
  the line above it. TOML, YAML and dotenv all use `#` comments.
- File: `.oraclint.yaml` (or `--config-file`) with `disable` (rule off
  everywhere) and `ignore` (rule off for path patterns: exact, `*` globs,
  `dir/**`). Unknown keys and unknown rule IDs are errors.
- A reason is **mandatory** everywhere. An inline directive without one (or
  naming an unknown rule) is not applied and produces an `info` finding
  `invalid-suppression`; a config entry without one is a usage error.
- Suppressed findings are kept and marked: counted in the text summary, listed
  with kind and reason in JSON, and emitted with SARIF `suppressions[]`
  (`inSource` or `external`) so GitHub closes the alert with the justification
  attached. Suppressions therefore stay visible in code review.
- Findings without a line (file permissions, missing token) can only be
  suppressed through the config file.

**Output**

Reports are rendered in memory and then written, so a failure never leaves a
truncated file; `--output` never writes through a symbolic link. Colors are
used only on a terminal and respect `NO_COLOR` and `--no-color`.

*Amended 2026-10-22:* scanned content can bring its own `.oraclint.yaml` and
directives, so a pull request could silence rules for itself. Rules disabled
by the config are now listed in every output format, and
`--ignore-suppressions` (Action input `ignore-suppressions`) ignores both the
config file and inline directives for untrusted content.

*Amended 2026-10-22 (first CI run):* report files were created with mode
`0600`. In the GitHub Action the scan runs as root (a GitHub requirement for
Docker actions) and later steps run as the runner user, so the SARIF file was
unreadable to the upload step. Reports are redacted, so they now use the
normal file mode (`0644` minus umask).

*Amended 2026-10-22 (second review):* there was no way to leave paths out of
a scan, so fixtures and intentionally unparsable files produced findings that
could not be suppressed (`parse-error` is not a rule). `exclude` entries in
the config (reason required, disclosed in every output, ignored in audit mode)
and the `--exclude` flag skip paths while walking directories; files named
explicitly are never excluded.

## Alternatives considered

- **Exit 1 for any error:** CI could not tell "insecure" from "broken scan".
- **Default `--fail-on high`:** friendlier on first run, but would let medium
  issues such as plaintext session cookies pass a default pipeline.
- **Dropping suppressed findings:** simpler output, but a malicious or careless
  change could hide a finding without anyone noticing.
- **Suppression comments without reasons:** convenient, but they accumulate
  and nobody remembers why they were added.

## Consequences

The line-based directive parser treats `#` inside a quoted string as a
comment. Such a directive has no valid reason and is reported as invalid, so
it can never suppress a finding by accident.
