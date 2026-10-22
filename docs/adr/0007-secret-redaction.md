# 7. Two-layer secret redaction

Date: 2026-10-22

## Status

Accepted

## Context

oraclint reads files whose main content is credentials. If a finding message,
a JSON field or a SARIF result ever echoes one, the tool turns a local secret
into one stored in CI logs and in GitHub's code scanning database, which is
worse than the misconfiguration it reports.

## Decision

1. **Rules never put values in messages.** They report key names, chain IDs,
   node names and host names only. Every rule has a test asserting this for
   its own secret inputs.
2. **The engine redacts every message** before it leaves the engine:
   - *Known secrets*: `redact.Collect` registers every string of a secrets
     file, every value under a sensitive-looking key (password, token, key,
     auth, ...) in config, dotenv, compose and Kubernetes files, and the
     secret parts of every URL (userinfo password, sensitive query values,
     key-like path segments). Exact occurrences are replaced by `****`.
   - *Patterns*: URLs in free text get their credentials masked and
     `password=value` style text is masked, even for values never registered.
3. The mask has a fixed length, so output does not reveal secret length.
4. Parse errors from the TOML/YAML libraries are reduced to a position plus a
   message with quoted fragments removed.
5. A fuzz test builds deployments full of random secrets, runs the complete
   pipeline with every rule **plus a deliberately leaky copy of each rule**
   that appends all raw values to its message, and fails if any secret
   survives. Reporter output is covered by the same test (see ADR 0008).

## Alternatives considered

- **Trusting rule authors:** one careless `fmt.Sprintf("%s", value)` would
  leak. Defense in depth is cheap here.
- **Never printing any value from files:** also hides useful non-secret
  context (hosts, node names), making findings harder to act on.

## Consequences

- Over-masking is possible: a harmless value under a key named like a secret
  is masked wherever it appears in messages. This is the intended bias.
- Values shorter than 4 characters and the words true/false/yes/no/on/off/
  null/none are never registered, to keep messages readable.
- Keys embedded in URL paths are recognized heuristically (segments of at
  least 20 characters containing a digit); shorter path tokens are a
  documented residual risk.
