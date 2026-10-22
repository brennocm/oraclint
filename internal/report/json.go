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
}

type jsonFinding struct {
	RuleID      string       `json:"rule_id"`
	Severity    string       `json:"severity"`
	Title       string       `json:"title"`
	Message     string       `json:"message"`
	Location    jsonLocation `json:"location"`
	Remediation string       `json:"remediation"`
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
	out.Summary = jsonSummary{FilesScanned: rep.FilesScanned, Total: counts.Total(), BySeverity: counts}

	for _, f := range rep.Findings {
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
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
