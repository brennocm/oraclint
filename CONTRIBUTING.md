# Contributing

Thanks for your interest in oraclint.

## Development

Requirements: the Go version declared in `go.mod`, `golangci-lint` and `govulncheck`.

```sh
make test-race   # unit and end-to-end tests with the race detector
make lint        # golangci-lint
make vuln        # govulncheck
make build       # builds bin/oraclint
```

CI runs exactly these Makefile targets.

## Adding a rule

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#adding-a-rule). Every rule needs:

1. a source file and a `_test.go` file in `internal/rules/`;
2. fixtures in `testdata/<RULE-ID>/vulnerable/` and `testdata/<RULE-ID>/safe/`;
3. documentation in `docs/rules/<RULE-ID>.md`;
4. a link to the official node documentation that confirms the key name and default.

Rules whose behaviour cannot be confirmed in the official documentation or the
node source must be marked `experimental`.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`,
`test:`, `docs:`, `refactor:`, `ci:`, `build:`, `chore:`). Every commit must build
and pass the tests.
