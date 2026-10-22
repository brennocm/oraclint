# 1. Record architecture decisions

Date: 2026-10-22

## Status

Accepted

## Context

oraclint is a security tool. Reviewers need to understand not only what it does
but why each non-obvious choice was made (parsing libraries, rule format,
exit codes, how secrets are handled).

## Decision

Record every significant decision as a short Architecture Decision Record in
`docs/adr/NNNN-title.md`, with the sections Context, Decision, Alternatives
considered and Consequences. ADRs are immutable once accepted; a later ADR
supersedes an earlier one instead of editing it.

## Alternatives considered

- **Design notes in the README:** mixes user and contributor documentation and
  loses the history of why something changed.
- **No written record:** decisions live only in commit messages and are hard to
  find.

## Consequences

Small overhead per decision, in exchange for a reviewable trail of trade-offs.
