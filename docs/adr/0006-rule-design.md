# 6. Rules as Go types with an explicit registry

Date: 2026-10-22

## Status

Accepted

## Context

oraclint ships about thirty checks. They need precise logic (defaults, URL
parsing, host classification), precise positions and stable metadata for
SARIF. Contributors and reviewers must be able to read a rule end to end.

## Decision

- A rule is a Go type implementing a two-method interface:
  `Metadata() Metadata` and `Check(*model.Target) []Finding`. Implementations
  are stateless empty structs, one per file, with a `_test.go` next to it.
- `rules.All()` lists every rule explicitly. There is no `init()`
  self-registration, so the set of shipped rules is visible in one place.
- IDs follow `NS-<AREA>-<NNN>` and never change once released.
- Documentation lives in `docs/rules/<ID>.md` and is embedded with `go:embed`
  (package `docs`, because embed cannot reach parent directories).
- Tests enforce the contract for every registered rule: unique, well-formed
  IDs; valid severity and status; at least one https reference; an embedded
  doc whose header and metadata table agree with the code; fixtures under
  `testdata/<ID>/vulnerable` (must fire) and `testdata/<ID>/safe` (must not).
- The engine sorts findings by file, line, column, rule ID and message, so
  output is byte-for-byte reproducible.

## Alternatives considered

- **Declarative rules (YAML, Rego, CEL):** attractive for user-defined policy,
  but our checks need real parsing logic (Postgres URLs, host classification,
  node merge semantics) that would end up as custom functions anyway, plus an
  extra interpreter dependency. Kept as a possible v0.2+ extension point.
- **`init()` registration:** less boilerplate, but hides which rules exist and
  makes registration order depend on file names.

## Consequences

Adding a rule touches four places (code, test, fixtures, doc) plus one line in
the registry; the tests fail if any of them is missing, which is the point.
