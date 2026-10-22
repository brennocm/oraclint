package rules

import (
	"strings"

	"github.com/brennocm/oraclint/internal/model"
)

// auditPlaintext flags audit events forwarded over http:// to a host on a
// public network. Audit events describe operator actions (logins, key
// exports, job changes); in transit they can be read or dropped.
type auditPlaintext struct{}

func (auditPlaintext) Metadata() Metadata {
	return Metadata{
		ID:          "NS-AUD-001",
		Title:       "Audit logs forwarded over plaintext",
		Severity:    SeverityLow,
		Targets:     []model.Kind{model.KindConfig},
		Status:      Stable,
		Remediation: "Use an https:// AuditLogger.ForwardToUrl, or forward to a collector on a private network.",
		References:  []string{refConfig + "#auditlogger"},
		CWE:         []string{"CWE-319"},
	}
}

func (r auditPlaintext) Check(t *model.Target) []Finding {
	if !t.TOML.Get("AuditLogger.Enabled").IsTrue() {
		return nil
	}
	f := t.TOML.Get("AuditLogger.ForwardToUrl")
	raw, _ := f.String()
	u, ok := parseURL(raw)
	if !ok || !strings.EqualFold(u.Scheme, "http") || isInternalHost(u.Hostname()) {
		return nil
	}
	return []Finding{newFinding(r.Metadata(), f.Loc,
		"AuditLogger.ForwardToUrl sends audit events over plaintext HTTP to %s", u.Hostname())}
}
