# 4. YAML library for compose and Kubernetes files

Date: 2026-10-22

## Status

Accepted

## Context

docker-compose files and Kubernetes manifests are YAML. We need node positions
and must survive hostile input (deep nesting, alias bombs).

## Decision

Use **`go.yaml.in/yaml/v3`**, the continuation of `gopkg.in/yaml.v3` maintained
by the YAML organization (the original repository was archived). Files are
parsed into `yaml.Node` trees, which carry `Line` and `Column` for every node.

We never decode into `interface{}` or structs. Aliases therefore stay as
`AliasNode`s, and our helpers (`model.MapGet`, `SeqItems`, ...) follow an
alias at most one level. This sidesteps "billion laughs" expansion entirely.

yaml.v3 errors have no structured position; we extract `line N` from the
message and discard the rest of the text, which may quote file content.

## Alternatives considered

- **`gopkg.in/yaml.v3`:** same code, but archived and no longer receiving fixes.
- **`sigs.k8s.io/yaml`:** converts YAML to JSON first and loses positions.
- **`github.com/goccy/go-yaml`:** has positions and an AST, but is a larger
  dependency with a different API; no advantage for our read-only use.

## Consequences

Rules work with `yaml.Node` directly, which is more verbose than typed structs
but keeps exact positions and avoids a large schema of compose/k8s types.
Helm templates are not valid YAML before rendering and are out of scope for v1
(see ADR 0005).
