// Package cli wires the oraclint commands together using cobra.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Exit codes returned by Execute. They are part of the public contract of the
// tool: CI pipelines rely on them.
const (
	ExitOK       = 0 // no findings at or above the --fail-on threshold
	ExitFindings = 1 // at least one finding at or above the --fail-on threshold
	ExitError    = 2 // usage error or runtime failure
)

// BuildInfo describes the binary being run.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

// NewRootCommand builds the command tree. It is separate from Execute so tests
// can run commands in-process with their own output buffers.
func NewRootCommand(info BuildInfo) *cobra.Command {
	root := &cobra.Command{
		Use:   "oraclint",
		Short: "Static security linter for Chainlink node deployments",
		Long: "oraclint scans Chainlink node configuration (config.toml, secrets.toml) and\n" +
			"deployment artifacts (docker-compose, Kubernetes manifests, .env files)\n" +
			"for insecure settings. It never connects to a running node.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newVersionCommand(info))
	return root
}

// Execute runs the CLI and returns the process exit code.
func Execute(info BuildInfo) int {
	root := NewRootCommand(info)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return ExitError
	}
	return ExitOK
}
