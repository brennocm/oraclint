package rules

import "testing"

func TestWebRateLimit(t *testing.T) {
	runRuleCases(t, webRateLimit{}, []ruleCase{
		{"relaxed count", cfg("[WebServer.RateLimit]\nUnauthenticated = 100\n"), []int{2}},
		{"short period only", cfg("[WebServer.RateLimit]\nUnauthenticatedPeriod = '1s'\n"), []int{2}},
		{"exactly at threshold", cfg("[WebServer.RateLimit]\nUnauthenticated = 30\nUnauthenticatedPeriod = '1m'\n"), nil},
		{"tighter than default", cfg("[WebServer.RateLimit]\nUnauthenticated = 3\nUnauthenticatedPeriod = '1m'\n"), nil},
		{"default", cfg(""), nil},
		{"zero period ignored", cfg("[WebServer.RateLimit]\nUnauthenticatedPeriod = '0s'\n"), nil},
	})
}
