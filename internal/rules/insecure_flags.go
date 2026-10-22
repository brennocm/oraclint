package rules

import "github.com/brennocm/oraclint/internal/model"

// insecureFlags flags any development-only [Insecure] setting. Production
// builds of the node reject these values at startup (Insecure.ValidateConfig),
// so this rule is an early warning: it catches the mistake in CI before a
// deployment fails, or before a dev build reaches production.
type insecureFlags struct{}

var insecureFlagKeys = []string{
	"Insecure.DevWebServer",
	"Insecure.OCRDevelopmentMode",
	"Insecure.InfiniteDepthQueries",
	"Insecure.DisableRateLimiting",
}

func (insecureFlags) Metadata() Metadata {
	return Metadata{
		ID:          "NS-INS-001",
		Title:       "Development-only [Insecure] flag enabled",
		Severity:    SeverityHigh,
		Targets:     []model.Kind{model.KindConfig},
		Status:      Stable,
		Remediation: "Remove the [Insecure] section from production configuration.",
		References:  []string{refConfig + "#insecure", refValidation},
		CWE:         []string{"CWE-489"},
	}
}

func (r insecureFlags) Check(t *model.Target) []Finding {
	var out []Finding
	for _, key := range insecureFlagKeys {
		f := t.TOML.Get(key)
		if f.IsTrue() {
			out = append(out, newFinding(r.Metadata(), f.Loc,
				"%s = true is a development-only setting; production node builds refuse to start with it", key))
		}
	}
	return out
}
