package cli

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/brennocm/oraclint/docs"
	"github.com/brennocm/oraclint/internal/rules"
)

func newRulesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "List and explain the built-in rules",
	}
	cmd.AddCommand(newRulesListCommand(), newRulesExplainCommand())
	return cmd
}

type ruleJSON struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Severity   string   `json:"severity"`
	Status     string   `json:"status"`
	Targets    []string `json:"targets"`
	CWE        []string `json:"cwe"`
	References []string `json:"references"`
}

func newRulesListCommand() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all rules",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			all := rules.All()
			switch format {
			case "json":
				out := make([]ruleJSON, 0, len(all))
				for _, r := range all {
					m := r.Metadata()
					out = append(out, ruleJSON{
						ID: m.ID, Title: m.Title, Severity: m.Severity.String(), Status: m.Status.String(),
						Targets: targetNames(m), CWE: nonNil(m.CWE), References: nonNil(m.References),
					})
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			case "text":
				tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "ID\tSEVERITY\tSTATUS\tTARGETS\tTITLE") //nolint:errcheck // checked by Flush
				for _, r := range all {
					m := r.Metadata()
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", //nolint:errcheck // checked by Flush
						m.ID, m.Severity, m.Status, strings.Join(targetNames(m), ","), m.Title)
				}
				return tw.Flush()
			default:
				return fmt.Errorf("unknown format %q (want text or json)", format)
			}
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "text", "output format: text or json")
	return cmd
}

func newRulesExplainCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "explain <RULE-ID>",
		Short: "Show the documentation of a rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, ok := rules.ByID(args[0])
			if !ok {
				return fmt.Errorf("unknown rule %q (see `oraclint rules list`)", args[0])
			}
			doc, err := fs.ReadFile(docs.Rules, "rules/"+r.Metadata().ID+".md")
			if err != nil {
				return fmt.Errorf("documentation for %s is missing: %w", r.Metadata().ID, err)
			}
			_, err = cmd.OutOrStdout().Write(doc)
			return err
		},
	}
}

func targetNames(m rules.Metadata) []string {
	out := make([]string, 0, len(m.Targets))
	for _, k := range m.Targets {
		out = append(out, k.String())
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
