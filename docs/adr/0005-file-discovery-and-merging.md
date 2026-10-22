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
| Other `*.toml` | secrets if every key belongs to the secrets schema; otherwise config if it has any top-level table of the config schema | weak |
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
- Directories are walked through an `os.Root` (Go 1.24+): the kernel resolves
  every open relative to the scan root and refuses to leave it, through
  symlinks or `..`, even if the tree changes during the scan. Symlinks with a
  relative target inside the root are followed; absolute targets are refused
  (os.Root policy), as are broken links and links leaving the root.
- `.git/` and `node_modules/` are skipped.

**Merging**

Files passed with repeated `--config` flags form one target, merged with the
node's semantics: later files override earlier ones, `[[EVM]]` entries merge by
`ChainID` and `[[EVM.Nodes]]` by `Name` (verified in chainlink-evm
`EVMConfigs.SetFrom` / `EVMNodes.SetFrom`). Each value keeps the location of the
file that set it. Config files discovered in a directory are analyzed
independently, because oraclint cannot know which ones a node loads together.

*Amended 2026-10-22:* the first version classified a TOML file as config only
when it had a table that exists exclusively in the config schema. The
end-to-end tests showed that a minimal `config.toml` containing only
`[WebServer]` (a table both schemas share) was silently skipped, a false
negative. Classification now compares every key path with the secrets schema
instead.

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
