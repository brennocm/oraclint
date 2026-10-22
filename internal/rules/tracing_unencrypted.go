package rules

import (
	"strings"

	"github.com/brennocm/oraclint/internal/model"
)

// tracingUnencrypted flags OTEL traces sent in plaintext to a collector on a
// public network. The node's own validation intends to allow unencrypted
// traces only to local collectors, but it only checks that CollectorTarget
// is a syntactically valid host:port (isValidLocalURI in
// core/config/toml/types.go, v2.69.0), so a remote host passes.
type tracingUnencrypted struct{}

func (tracingUnencrypted) Metadata() Metadata {
	return Metadata{
		ID:          "NS-TRC-001",
		Title:       "Traces exported unencrypted to a remote collector",
		Severity:    SeverityMedium,
		Targets:     []model.Kind{model.KindConfig},
		Status:      Stable,
		Remediation: "Use Tracing.Mode = 'tls' with Tracing.TLSCertPath, or send traces to a collector on the same host or private network.",
		References:  []string{refConfig + "#tracing", refValidation},
		CWE:         []string{"CWE-319"},
	}
}

func (r tracingUnencrypted) Check(t *model.Target) []Finding {
	doc := t.TOML
	if !doc.Get("Tracing.Enabled").IsTrue() {
		return nil
	}
	mode := doc.Get("Tracing.Mode")
	if m, _ := mode.String(); !strings.EqualFold(m, "unencrypted") {
		return nil
	}
	target, _ := doc.Get("Tracing.CollectorTarget").String()
	host := endpointHost(target)
	if isInternalHost(host) {
		return nil
	}
	return []Finding{newFinding(r.Metadata(), mode.Loc,
		"Tracing.Mode = 'unencrypted' sends traces in plaintext to remote collector %s", host)}
}
