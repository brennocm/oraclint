package rules

import "github.com/brennocm/oraclint/internal/model"

// webHTTPSDisabled flags WebServer.TLS.HTTPSPort = 0 while the plaintext
// listener is on. The node then serves the operator UI and API, including
// login and session cookies, only over HTTP (core/cmd/shell.go runs the TLS
// server only when HTTPSPort != 0).
type webHTTPSDisabled struct{}

func (webHTTPSDisabled) Metadata() Metadata {
	return Metadata{
		ID:          "NS-WEB-001",
		Title:       "Operator UI served without HTTPS",
		Severity:    SeverityMedium,
		Targets:     []model.Kind{model.KindConfig},
		Status:      Stable,
		Remediation: "Configure WebServer.TLS (CertPath, KeyPath, HTTPSPort), or terminate TLS at a reverse proxy and suppress this finding with that reason.",
		References:  []string{refConfig + "#webservertls", refBestPractic},
		CWE:         []string{"CWE-319"},
	}
}

func (r webHTTPSDisabled) Check(t *model.Target) []Finding {
	https := t.TOML.Get("WebServer.TLS.HTTPSPort")
	httpPort, _ := t.TOML.Get("WebServer.HTTPPort").Int()
	if port, ok := https.Int(); !ok || port != 0 || httpPort == 0 {
		return nil
	}
	return []Finding{newFinding(r.Metadata(), https.Loc,
		"WebServer.TLS.HTTPSPort = 0 disables HTTPS; the operator UI and API are only served over plaintext HTTP on port %d", httpPort)}
}
