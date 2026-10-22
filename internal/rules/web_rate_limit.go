package rules

import (
	"time"

	"github.com/brennocm/oraclint/internal/model"
)

// webRateLimit flags an unauthenticated rate limit (which throttles login
// attempts) relaxed well beyond the node default of 5 requests per 20s.
// Experimental: the right threshold depends on the deployment.
type webRateLimit struct{}

// maxUnauthenticatedPerMinute is twice the node default (15/min).
const maxUnauthenticatedPerMinute = 30

func (webRateLimit) Metadata() Metadata {
	return Metadata{
		ID:          "NS-WEB-007",
		Title:       "Login rate limit relaxed",
		Severity:    SeverityLow,
		Targets:     []model.Kind{model.KindConfig},
		Status:      Experimental,
		Remediation: "Keep WebServer.RateLimit.Unauthenticated / UnauthenticatedPeriod near the default (5 per 20s).",
		References:  []string{refConfig + "#webserverratelimit"},
		CWE:         []string{"CWE-307"},
	}
}

func (r webRateLimit) Check(t *model.Target) []Finding {
	count := t.TOML.Get("WebServer.RateLimit.Unauthenticated")
	period := t.TOML.Get("WebServer.RateLimit.UnauthenticatedPeriod")
	if !count.Set && !period.Set {
		return nil
	}
	n, okN := count.Int()
	d, okD := period.Duration()
	if !okN || !okD || d <= 0 {
		return nil
	}
	perMinute := float64(n) * float64(time.Minute) / float64(d)
	if perMinute <= maxUnauthenticatedPerMinute {
		return nil
	}
	loc := count.Loc
	if !count.Set {
		loc = period.Loc
	}
	return []Finding{newFinding(r.Metadata(), loc,
		"unauthenticated requests are limited to %d per %s (%.0f/min), more than %d/min makes password guessing easier",
		n, d, perMinute, maxUnauthenticatedPerMinute)}
}
