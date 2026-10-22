# 3. TOML parsing and key positions

Date: 2026-10-22

## Status

Accepted

## Context

Every finding must point to `file:line`. The node configuration is TOML, so we
need a TOML library that either exposes positions or lets us compute them.
Requirements: full TOML 1.0 support (dotted keys, arrays of tables, inline
tables), no panics on hostile input, few dependencies.

## Decision

Use **`github.com/pelletier/go-toml/v2`** (v2.4.3) in two passes:

1. `toml.Unmarshal` into `map[string]any` decodes values with full spec
   compliance (escapes, integer formats, dates, duplicate-key detection).
2. The low-level `unstable.Parser` walks the same input and records the byte
   offset of every key. Offsets are converted to line/column with our own line
   index (binary search), because `Parser.Shape` rescans the input from the
   start on every call, which is quadratic on large files.

Both passes produce paths in the same format (`EVM[0].Nodes[1].HTTPURL`), and
`model.Value` attaches the recorded location to each decoded value. Values
without their own position (elements of plain arrays) inherit their parent's.

The node itself uses go-toml/v2 (via chainlink-common), so we parse with the
same library family as the software we analyze.

Parse error messages have quoted fragments stripped, since the decoder can
echo part of the offending line, which may be a secret.

## Alternatives considered

- **`github.com/BurntSushi/toml`:** `MetaData.Keys()` lists keys but the
  library does not expose a reliable per-key position API; we would have to
  rescan the file anyway.
- **Only the unstable parser:** gives positions directly, but we would have to
  reimplement value decoding (string escapes, integer bases, dates) and TOML's
  table-redefinition rules. More code, more bugs.
- **Decode + line scan with regexes:** fragile with dotted keys, inline tables,
  repeated `[[EVM.Nodes]]` blocks and multi-line strings.

## Consequences

- Each TOML file is parsed twice. Node config files are a few KB, so the cost
  is irrelevant compared to correctness.
- `unstable` is explicitly not covered by go-toml's compatibility promise. The
  API surface we use is small (`Parser`, `Node.Key/Value/Children`, `Raw`) and
  is covered by our position tests, so an upstream change fails loudly in CI.
- Keys containing a literal `.` cannot be told apart from nested keys in our
  path strings. No node key contains dots; user-defined maps such as
  `Tracing.Attributes` are not used by any rule.
