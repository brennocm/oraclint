// Package cli wires the oraclint commands together using cobra.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

// Exit codes returned by Execute. They are part of the public contract of the
// tool: CI pipelines rely on them (see ADR 0009).
const (
	ExitOK       = 0 // no active findings at or above the --fail-on threshold
	ExitFindings = 1 // at least one active finding at or above the threshold
	ExitError    = 2 // usage error or runtime failure
)

// BuildInfo describes the binary being run.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

// errFindings signals "the scan worked and found problems": exit code 1
// without an error message.
var errFindings = errors.New("findings at or above the failure threshold")

// NewRootCommand builds the command tree. It is separate from Execute so tests
// can run commands in-process with their own output buffers.
func NewRootCommand(info BuildInfo) *cobra.Command {
	root := &cobra.Command{
		Use:   "oraclint",
		Short: "Static security linter for Chainlink node deployments",
		Long: "oraclint scans Chainlink node configuration (config.toml, secrets.toml) and\n" +
			"deployment artifacts (docker-compose, Kubernetes manifests, .env files)\n" +
			"for insecure settings. It never connects to a running node.\n\n" +
			"Not affiliated with Chainlink Labs.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newVersionCommand(info), newScanCommand(info), newRulesCommand())
	return root
}

// Execute runs the CLI with the process arguments and returns the exit code.
func Execute(info BuildInfo) int {
	return run(NewRootCommand(info), os.Stderr)
}

func run(root *cobra.Command, stderr io.Writer) int {
	err := root.Execute()
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, errFindings):
		return ExitFindings
	default:
		fmt.Fprintln(stderr, "Error:", err) //nolint:errcheck // nothing useful to do if stderr fails
		return ExitError
	}
}
