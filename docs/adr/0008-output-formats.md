# 8. Output formats without extra dependencies

Date: 2026-10-22

## Status

Accepted

## Context

oraclint prints results for humans (terminal), for scripts (JSON) and for
GitHub code scanning (SARIF 2.1.0). Each format could pull in a library: a
SARIF SDK, a terminal color package. For a security tool, every dependency is
code we ship to CI runners that hold secrets.

## Decision

- **SARIF:** hand-written Go structs covering only what we emit (driver with
  the full rule catalog, results with physical locations). Correctness is
  checked by validating the output against the official SARIF 2.1.0 JSON
  schema in a test (the schema is vendored in `testdata/sarif/`, the validator
  `santhosh-tekuri/jsonschema` is a test-only dependency) and by golden files.
  Each rule carries `properties.security-severity` so GitHub ranks alerts.
  Paths are relative to the scan root with `uriBaseId: %SRCROOT%`.
- **Text:** ANSI escape codes written directly. Color is used only when the
  output is a terminal, `NO_COLOR` is unset and `--no-color` is not given.
- **JSON:** a documented, versioned schema (`schema_version`, see
  `docs/output-json.md`); empty results are `[]`, never `null`.
- All formats are covered by golden files (`make golden-update` regenerates
  them; the diff is reviewed like code).

## Alternatives considered

- **`github.com/owenrumney/go-sarif`:** complete and convenient, but brings a
  large API surface to produce ~80 lines of structs.
- **`github.com/fatih/color`:** pulls `go-colorable` and `go-isatty`; terminal
  detection is a one-line `os.File.Stat` check in the standard library.

## Consequences

If GitHub starts requiring SARIF fields we do not model, we add them to our
structs; the schema test keeps us honest. Colors on legacy Windows consoles
without VT support are not handled (`--no-color` or `NO_COLOR` works around it).
