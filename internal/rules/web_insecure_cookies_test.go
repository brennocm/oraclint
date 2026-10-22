package rules

import "testing"

func TestWebInsecureCookies(t *testing.T) {
	runRuleCases(t, webInsecureCookies{}, []ruleCase{
		{"disabled", cfg("[WebServer]\nSecureCookies = false\n"), []int{2}},
		{"enabled", cfg("[WebServer]\nSecureCookies = true\n"), nil},
		{"default", cfg("[WebServer]\nHTTPPort = 6688\n"), nil},
	})
}
