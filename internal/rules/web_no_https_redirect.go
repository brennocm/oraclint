package rules

import "github.com/brennocm/oraclint/internal/model"

// webNoHTTPSRedirect flags a node that has TLS configured but still serves
// the plaintext listener without redirecting to HTTPS. Users who type the
// http:// URL (or old bookmarks) then log in over plaintext.
type webNoHTTPSRedirect struct{}

func (webNoHTTPSRedirect) Metadata() Metadata {
	return Metadata{
		ID:          "NS-WEB-004",
		Title:       "HTTP not redirected to HTTPS",
		Severity:    SeverityLow,
		Targets:     []model.Kind{model.KindConfig},
		Status:      Stable,
		Remediation: "Set WebServer.TLS.ForceRedirect = true, or disable the plaintext listener with WebServer.HTTPPort = 0.",
		References:  []string{refConfig + "#forceredirect"},
		CWE:         []string{"CWE-319"},
	}
}

func (r webNoHTTPSRedirect) Check(t *model.Target) []Finding {
	doc := t.TOML
	httpsPort := doc.Get("WebServer.TLS.HTTPSPort")
	if port, _ := httpsPort.Int(); port == 0 {
		return nil // HTTPS off: NS-WEB-001's territory
	}
	// Only judge nodes where TLS was deliberately configured; the default
	// HTTPSPort alone does not mean the operator set up certificates.
	tlsConfigured := httpsPort.Set || doc.Get("WebServer.TLS.CertPath").Set || doc.Get("WebServer.TLS.KeyPath").Set
	if !tlsConfigured {
		return nil
	}
	if httpPort, _ := doc.Get("WebServer.HTTPPort").Int(); httpPort == 0 {
		return nil
	}
	redirect := doc.Get("WebServer.TLS.ForceRedirect")
	if redirect.IsTrue() {
		return nil
	}
	return []Finding{newFinding(r.Metadata(), redirect.Loc,
		"TLS is configured but WebServer.TLS.ForceRedirect is not enabled, so the plaintext HTTP listener still serves the UI")}
}
