package rules

import "github.com/brennocm/oraclint/internal/model"

// dbSimplePasswords flags AllowSimplePasswords, which skips the node's
// database password complexity check. Production builds reject it
// (DatabaseSecrets.validateConfig), so this is an early warning, also for
// the CL_DATABASE_ALLOW_SIMPLE_PASSWORDS environment variable.
type dbSimplePasswords struct{}

const envAllowSimplePasswords = "CL_DATABASE_ALLOW_SIMPLE_PASSWORDS" //nolint:gosec // an environment variable name, not a credential

func (dbSimplePasswords) Metadata() Metadata {
	return Metadata{
		ID:          "NS-DB-004",
		Title:       "Simple database passwords allowed",
		Severity:    SeverityMedium,
		Targets:     []model.Kind{model.KindSecrets, model.KindEnv, model.KindCompose, model.KindK8s},
		Status:      Stable,
		Remediation: "Remove AllowSimplePasswords / CL_DATABASE_ALLOW_SIMPLE_PASSWORDS and use a database password of at least 16 characters.",
		References:  []string{refSecrets + "#allowsimplepasswords", refValidation},
		CWE:         []string{"CWE-521"},
	}
}

func (r dbSimplePasswords) Check(t *model.Target) []Finding {
	if t.Kind == model.KindSecrets {
		f := t.TOML.Get("Database.AllowSimplePasswords")
		if !f.IsTrue() {
			return nil
		}
		return []Finding{newFinding(r.Metadata(), f.Loc,
			"Database.AllowSimplePasswords = true disables the database password complexity check; production node builds refuse to start with it")}
	}
	var out []Finding
	for _, e := range envAssignments(t) {
		if e.Name == envAllowSimplePasswords && e.Literal && envTrue(e.Value) {
			out = append(out, newFinding(r.Metadata(), e.Loc,
				"%s=true disables the database password complexity check; production node builds refuse to start with it", e.Name))
		}
	}
	return out
}
