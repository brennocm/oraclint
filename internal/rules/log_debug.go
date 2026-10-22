package rules

import (
	"strings"

	"github.com/brennocm/oraclint/internal/model"
)

// logDebug flags Log.Level = 'debug'. Debug logs include request details,
// job pipeline data and (with Database.LogQueries) SQL statements, and they
// grow fast enough to hide real problems.
type logDebug struct{}

func (logDebug) Metadata() Metadata {
	return Metadata{
		ID:          "NS-LOG-001",
		Title:       "Debug log level",
		Severity:    SeverityLow,
		Targets:     []model.Kind{model.KindConfig},
		Status:      Stable,
		Remediation: "Use Log.Level = 'info' (the default) or higher in production; enable debug temporarily when investigating.",
		References:  []string{refConfig + "#log"},
		CWE:         []string{"CWE-532"},
	}
}

func (r logDebug) Check(t *model.Target) []Finding {
	f := t.TOML.Get("Log.Level")
	if level, _ := f.String(); !strings.EqualFold(level, "debug") {
		return nil
	}
	return []Finding{newFinding(r.Metadata(), f.Loc,
		"Log.Level = 'debug' writes verbose operational data to the console logs")}
}
