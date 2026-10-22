package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

func newVersionCommand(info BuildInfo) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "oraclint %s\ncommit: %s\nbuilt: %s\ngo: %s\n",
				info.Version, info.Commit, info.Date, runtime.Version())
			return err
		},
	}
}
