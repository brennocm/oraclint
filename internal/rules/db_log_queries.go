package rules

import "github.com/brennocm/oraclint/internal/model"

// dbLogQueries flags Database.LogQueries = true: SQL statements, including
// the values they carry, end up in the node logs and in whatever system the
// logs are shipped to.
type dbLogQueries struct{}

func (dbLogQueries) Metadata() Metadata {
	return Metadata{
		ID:          "NS-DB-001",
		Title:       "SQL query logging enabled",
		Severity:    SeverityMedium,
		Targets:     []model.Kind{model.KindConfig},
		Status:      Stable,
		Remediation: "Remove Database.LogQueries (default false); use Postgres statement logging on the database side if needed.",
		References:  []string{refConfig + "#logqueries"},
		CWE:         []string{"CWE-532"},
	}
}

func (r dbLogQueries) Check(t *model.Target) []Finding {
	f := t.TOML.Get("Database.LogQueries")
	if !f.IsTrue() {
		return nil
	}
	return []Finding{newFinding(r.Metadata(), f.Loc,
		"Database.LogQueries = true logs SQL statements, which can contain job data and other sensitive values")}
}
