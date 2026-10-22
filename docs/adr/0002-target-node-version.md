# 2. Pin rules to a verified node version

Date: 2026-10-22

## Status

Accepted

## Context

Rules depend on exact key names and default values of the Chainlink node
configuration. These change between releases: keys get deprecated (for example
`InsecurePPROFHeap` now has no effect), defaults move, and new sections appear.
A rule built on a wrong default either floods users with false positives or,
worse, stays silent.

## Decision

- Every rule is verified against a single **target node version**, currently
  **v2.69.0** (released 2026-10-19).
- Sources of truth, in order: the node source code at that tag (validation in
  `core/config/toml/types.go`, runtime behaviour in `core/cmd` and `core/web`),
  then the generated `docs/CONFIG.md` and `docs/SECRETS.md`, then docs.chain.link.
- Defaults used by rules live in one place (`internal/model/defaults.go`), each
  with a comment linking to its source.
- A rule that cannot be confirmed is either not written or marked `experimental`.
- Research notes and links are kept in [`docs/research.md`](../research.md).

## Alternatives considered

- **Track the latest docs site without a pinned version:** convenient, but the
  site changes silently and rules cannot cite what they were verified against.
- **Support many node versions with version-specific rules:** more accurate for
  old deployments but far more complexity than a v1 needs. Left as future work.

## Consequences

Bumping the target version is an explicit task: re-check `defaults.go`, rerun
the rule tests and update this ADR. Deployments on much older node versions may
see findings that do not apply to them; the README documents this limitation.
