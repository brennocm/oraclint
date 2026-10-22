package rules

import (
	"time"

	"github.com/brennocm/oraclint/internal/model"
)

// webSessionTimeout flags idle session timeouts longer than an hour. Long
// idle sessions widen the window for a stolen or forgotten session (an
// unlocked workstation, a cookie copied from a browser profile).
type webSessionTimeout struct{}

// maxSessionTimeout is the longest idle timeout accepted. The node default is
// 15 minutes; one hour leaves room for convenience without allowing
// day-long sessions.
const maxSessionTimeout = time.Hour

func (webSessionTimeout) Metadata() Metadata {
	return Metadata{
		ID:          "NS-WEB-005",
		Title:       "Long idle session timeout",
		Severity:    SeverityLow,
		Targets:     []model.Kind{model.KindConfig},
		Status:      Stable,
		Remediation: "Keep the session timeout at or below 1h (node default: 15m).",
		References:  []string{refConfig + "#sessiontimeout"},
		CWE:         []string{"CWE-613"},
	}
}

func (r webSessionTimeout) Check(t *model.Target) []Finding {
	keys := []string{"WebServer.SessionTimeout"}
	method, _ := t.TOML.Get("WebServer.AuthenticationMethod").String()
	switch method {
	case "ldap":
		keys = append(keys, "WebServer.LDAP.SessionTimeout")
	case "oidc":
		keys = append(keys, "WebServer.OIDC.SessionTimeout")
	}

	var out []Finding
	for _, key := range keys {
		f := t.TOML.Get(key)
		d, ok := f.Duration()
		if !ok || !f.Set || d <= maxSessionTimeout {
			continue
		}
		out = append(out, newFinding(r.Metadata(), f.Loc,
			"%s = %s keeps idle sessions alive for more than %s", key, d, maxSessionTimeout))
	}
	return out
}
