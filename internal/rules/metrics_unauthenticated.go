package rules

import "github.com/brennocm/oraclint/internal/model"

// metricsUnauthenticated flags a secrets file without Prometheus.AuthToken.
// Without it the /metrics endpoint answers anyone who can reach the web
// server (core/web/router.go: prometheusHandler skips the check when the
// token is empty). Experimental: the token may come from
// CL_PROMETHEUS_AUTH_TOKEN instead, which a file scan cannot see.
type metricsUnauthenticated struct{}

func (metricsUnauthenticated) Metadata() Metadata {
	return Metadata{
		ID:          "NS-MET-001",
		Title:       "Prometheus metrics endpoint without authentication",
		Severity:    SeverityLow,
		Targets:     []model.Kind{model.KindSecrets},
		Status:      Experimental,
		Remediation: "Set Prometheus.AuthToken in secrets.toml (or CL_PROMETHEUS_AUTH_TOKEN) and configure the scraper with the bearer token.",
		References:  []string{refSecrets + "#prometheus"},
		CWE:         []string{"CWE-306"},
	}
}

func (r metricsUnauthenticated) Check(t *model.Target) []Finding {
	if token, _ := t.TOML.Get("Prometheus.AuthToken").String(); token != "" {
		return nil
	}
	return []Finding{newFinding(r.Metadata(), model.Location{File: t.Path},
		"no Prometheus.AuthToken is set, so /metrics is readable without authentication")}
}
