package report

import (
	"encoding/json"
	"io"
)

// JSONSchemaVersion is bumped on any breaking change to the JSON output.
// See docs/output-json.md.
const JSONSchemaVersion = "1"

type jsonReport struct {
	SchemaVersion string        `json:"schema_version"`
	Tool          jsonTool      `json:"tool"`
	Summary       jsonSummary   `json:"summary"`
	Findings      []jsonFinding `json:"findings"`
}

type jsonTool struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"information_uri"`
}

type jsonSummary struct {
	FilesScanned int    `json:"files_scanned"`
	Total        int    `json:"total"`
	BySeverity   Counts `json:"by_severity"`
	Suppressed   int    `json:"suppressed"`
	// DisabledRules is always present ([] when none), see docs/output-json.md.
	DisabledRules []DisabledRule `json:"disabled_rules"`
	// ExcludedPaths is always present ([] when none).
	ExcludedPaths []ExcludedPath `json:"excluded_paths"`
}

type jsonFinding struct {
	RuleID      string           `json:"rule_id"`
	Severity    string           `json:"severity"`
	Title       string           `json:"title"`
	Message     string           `json:"message"`
	Location    jsonLocation     `json:"location"`
	Remediation string           `json:"remediation"`
	Suppression *jsonSuppression `json:"suppression,omitempty"`
}

type jsonSuppression struct {
	Kind   string       `json:"kind"`
	Reason string       `json:"reason"`
	Source jsonLocation `json:"source"`
}

type jsonLocation struct {
	File   string `json:"file"`
	Line   int    `json:"line,omitempty"`
	Column int    `json:"column,omitempty"`
}

func writeJSON(w io.Writer, rep Report) error {
	out := jsonReport{
		SchemaVersion: JSONSchemaVersion,
		Tool:          jsonTool{Name: "oraclint", Version: rep.ToolVersion, InformationURI: InformationURI},
		Findings:      make([]jsonFinding, 0, len(rep.Findings)), // [] rather than null when empty
	}
	counts := countBySeverity(rep.Findings)
	out.Summary = jsonSummary{
		FilesScanned:  rep.FilesScanned,
		Total:         counts.Total(),
		BySeverity:    counts,
		Suppressed:    countSuppressed(rep.Findings),
		DisabledRules: append([]DisabledRule{}, rep.Disabled...),
		ExcludedPaths: append([]ExcludedPath{}, rep.Excluded...),
	}

	for _, f := range rep.Findings {
		var sup *jsonSuppression
		if f.Suppression != nil {
			sup = &jsonSuppression{
				Kind:   f.Suppression.Kind,
				Reason: f.Suppression.Reason,
				Source: jsonLocation{
					File: relativePath(rep.BaseDir, f.Suppression.Source.File),
					Line: f.Suppression.Source.Line, Column: f.Suppression.Source.Column,
				},
			}
		}
		out.Findings = append(out.Findings, jsonFinding{
			RuleID:   f.RuleID,
			Severity: f.Severity.String(),
			Title:    f.Title,
			Message:  f.Message,
			Location: jsonLocation{
				File:   relativePath(rep.BaseDir, f.Location.File),
				Line:   f.Location.Line,
				Column: f.Location.Column,
			},
			Remediation: f.Remediation,
			Suppression: sup,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
