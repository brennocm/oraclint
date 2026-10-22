# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `oraclint scan` for Chainlink node `config.toml` and `secrets.toml`,
  docker-compose files, Kubernetes manifests and dotenv files, with text, JSON
  (schema version 1) and SARIF 2.1.0 output.
- 35 rules (32 stable, 3 experimental) verified against node v2.69.0, each with
  embedded documentation (`oraclint rules list`, `oraclint rules explain`).
- Node-accurate semantics: documented defaults for absent keys, merging of
  multiple `--config` files.
- Inline (`# oraclint:ignore ID reason="..."`) and `.oraclint.yaml`
  suppressions with mandatory reasons, reported as suppressed in JSON and SARIF.
- `--ignore-suppressions` audit mode (Action input `ignore-suppressions`) for
  untrusted content; rules disabled by `.oraclint.yaml` are listed in every
  output format.
- Secret redaction across all outputs, enforced by a fuzz test; control
  characters and bidirectional overrides from scanned files are escaped.
- YAML merge keys (`<<: *anchor`) are followed and duplicate keys reported.
- Exit codes 0 (clean), 1 (findings at or above `--fail-on`), 2 (error).
- GitHub Action, multi-arch container image, signed release archives with
  SBOMs and build provenance.
