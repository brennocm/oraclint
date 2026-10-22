package rules

import "github.com/brennocm/oraclint/internal/model"

// webInsecureCookies flags WebServer.SecureCookies = false: session cookies
// are then sent over plaintext HTTP as well, where they can be captured and
// replayed to take over an operator session.
type webInsecureCookies struct{}

func (webInsecureCookies) Metadata() Metadata {
	return Metadata{
		ID:          "NS-WEB-002",
		Title:       "Session cookies without the Secure flag",
		Severity:    SeverityMedium,
		Targets:     []model.Kind{model.KindConfig},
		Status:      Stable,
		Remediation: "Remove WebServer.SecureCookies (default true) and access the UI over HTTPS.",
		References:  []string{refConfig + "#securecookies"},
		CWE:         []string{"CWE-614"},
	}
}

func (r webInsecureCookies) Check(t *model.Target) []Finding {
	f := t.TOML.Get("WebServer.SecureCookies")
	if b, ok := f.Bool(); !ok || b {
		return nil
	}
	return []Finding{newFinding(r.Metadata(), f.Loc,
		"WebServer.SecureCookies = false lets session cookies travel over plaintext HTTP, where they can be stolen and replayed")}
}
