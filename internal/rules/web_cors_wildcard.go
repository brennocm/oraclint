package rules

import (
	"strings"

	"github.com/brennocm/oraclint/internal/model"
)

// webCORSWildcard flags a "*" entry in WebServer.AllowOrigins. The node splits
// the value on commas and gin-contrib/cors (v1.7.2) switches to
// AllowAllOrigins as soon as any entry is "*", answering every origin with
// "Access-Control-Allow-Origin: *". Browsers refuse to expose credentialed
// responses for "*", which limits the impact, but any website can still send
// requests to the API and the docs recommend explicit origins.
type webCORSWildcard struct{}

func (webCORSWildcard) Metadata() Metadata {
	return Metadata{
		ID:          "NS-WEB-003",
		Title:       "Wildcard CORS origin",
		Severity:    SeverityMedium,
		Targets:     []model.Kind{model.KindConfig},
		Status:      Stable,
		Remediation: "Set WebServer.AllowOrigins to the exact URL(s) used to reach the operator UI.",
		References:  []string{refConfig + "#alloworigins"},
		CWE:         []string{"CWE-942"},
	}
}

func (r webCORSWildcard) Check(t *model.Target) []Finding {
	f := t.TOML.Get("WebServer.AllowOrigins")
	s, ok := f.String()
	if !ok {
		return nil
	}
	for _, origin := range strings.Split(s, ",") {
		if strings.TrimSpace(origin) == "*" {
			return []Finding{newFinding(r.Metadata(), f.Loc,
				"WebServer.AllowOrigins contains '*', which allows any website to make cross-origin requests to the node API")}
		}
	}
	return nil
}
