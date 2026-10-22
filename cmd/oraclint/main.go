// Command oraclint is a static security linter for Chainlink node deployments.
package main

import (
	"os"

	"github.com/brennocm/oraclint/internal/cli"
)

// Build metadata, injected at link time with -ldflags "-X main.version=...".
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	os.Exit(cli.Execute(cli.BuildInfo{Version: version, Commit: commit, Date: date}))
}
