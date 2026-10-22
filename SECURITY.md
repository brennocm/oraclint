# Security Policy

## Supported versions

Only the latest released version of oraclint receives security fixes.

## Reporting a vulnerability

Please **do not** open a public issue for security problems in oraclint itself
(for example: a crafted file that crashes or hangs the scanner, a secret value
leaking into any output, or a tampered release artifact).

Report privately through
[GitHub Security Advisories](https://github.com/brennocm/oraclint/security/advisories/new).
Include the oraclint version, the command you ran and, if possible, a minimal
input file that reproduces the issue (with any real secrets removed).

You can expect an acknowledgement within 7 days. Once a fix is released, the
advisory will be published with credit to the reporter unless you prefer
otherwise.

## Scope

oraclint is a static analyzer. Misconfigurations it fails to detect are bugs,
not vulnerabilities; please report them as regular issues. Vulnerabilities in
the Chainlink node itself should be reported to Chainlink Labs, not here.
