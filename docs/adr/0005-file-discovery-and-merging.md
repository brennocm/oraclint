# 5. File discovery, classification and config merging

Date: 2026-10-22

## Status

Accepted

## Context

Users point oraclint at a repository or directory. We must find the node's
files among unrelated ones (other projects also have `config.toml` and
`*.yaml`), without false negatives from silently skipped files and without
being abusable by a malicious repository (for example in a pull request scan).

## Decision

**Classification**

| Signal | Example | Strength |
|---|---|---|
| Compose name | `docker-compose*.y(a)ml`, `compose*.y(a)ml` | strong |
| Dotenv name | `.env`, `.env.*`, `*.env` (not `.example/.sample/.template/.dist/.tmpl`) | strong |
| `config.toml`, `*secret*.toml` | | strong (content still decides config vs. secrets) |
| Other `*.toml` | config if it has a config-only top-level table, secrets if it has a secrets-only table or `Database.URL` | weak |
| Other `*.y(a)ml` | Kubernetes if a document has `apiVersion` and `kind` | weak |
| `--config/--secrets/--compose/--k8s/--env` flags | any file name | strong |

Parse errors and oversized files with a **strong** signal are reported as
findings. Weak candidates that fail to parse are skipped (debug log), because
they are usually not node files. Weak YAML containing `{{` (Helm/Go templates)
is skipped before parsing.

**Safety limits**

- Files larger than 5 MiB are not read (`io.LimitReader`, so a file that grows
  during the scan is still bounded).
- Only regular files are read (no FIFOs or devices).
- Symlinks are followed only if they resolve inside the scan root.
- `.git/` and `node_modules/` are skipped.

**Merging**

Files passed with repeated `--config` flags form one target, merged with the
node's semantics: later files override earlier ones, `[[EVM]]` entries merge by
`ChainID` and `[[EVM.Nodes]]` by `Name` (verified in chainlink-evm
`EVMConfigs.SetFrom` / `EVMNodes.SetFrom`). Each value keeps the location of the
file that set it. Config files discovered in a directory are analyzed
independently, because oraclint cannot know which ones a node loads together.

## Alternatives considered

- **Merge every config file found in a directory:** wrong when a repository
  holds several nodes' configs, and the order would be arbitrary.
- **Report every unparsable YAML/TOML file:** floods users with errors for Helm
  charts and unrelated tools.
- **Follow all symlinks:** lets a malicious repository point oraclint at files
  outside the checkout.

## Consequences

The `CL_CONFIG` environment variable (applied last by the node) is not modeled
in v1. Users with split configs must pass them explicitly with `--config` to get
merged results. Helm charts must be rendered (`helm template`) before scanning.
