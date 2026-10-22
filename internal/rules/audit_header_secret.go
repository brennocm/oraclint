package rules

import (
	"regexp"
	"strings"

	"github.com/brennocm/oraclint/internal/model"
)

// auditHeaderSecret flags credentials in AuditLogger.Headers. Unlike other
// credentials, these headers have no secrets.toml counterpart, so they sit in
// the (usually committed) config file.
type auditHeaderSecret struct{}

var credentialHeader = regexp.MustCompile(`(?i)authorization|token|api[-_]?key|secret|cookie|password`)

func (auditHeaderSecret) Metadata() Metadata {
	return Metadata{
		ID:          "NS-SEC-002",
		Title:       "Credential in AuditLogger headers",
		Severity:    SeverityMedium,
		Targets:     []model.Kind{model.KindConfig},
		Status:      Stable,
		Remediation: "Keep the file that sets AuditLogger.Headers out of version control (for example inject it with CL_CONFIG from a secret store) and rotate the credential.",
		References:  []string{refConfig + "#headers"},
		CWE:         []string{"CWE-260"},
	}
}

func (r auditHeaderSecret) Check(t *model.Target) []Finding {
	var out []Finding
	for _, h := range t.TOML.Root.Get("AuditLogger.Headers").Items() {
		header, ok := h.Scalar.(string)
		if !ok {
			continue
		}
		name, value, found := strings.Cut(header, ":")
		if !found || strings.TrimSpace(value) == "" || !credentialHeader.MatchString(name) {
			continue
		}
		out = append(out, newFinding(r.Metadata(), h.Loc,
			"AuditLogger.Headers sets a %q header with a credential in the config file", strings.TrimSpace(name)))
	}
	return out
}
