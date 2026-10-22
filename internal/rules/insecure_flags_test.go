package rules

import "testing"

func TestInsecureFlags(t *testing.T) {
	runRuleCases(t, insecureFlags{}, []ruleCase{
		{"one flag", cfg("[Insecure]\nDevWebServer = true\n"), []int{2}},
		{"all flags", cfg("[Insecure]\nDevWebServer = true\nOCRDevelopmentMode = true\nInfiniteDepthQueries = true\nDisableRateLimiting = true\n"), []int{2, 3, 4, 5}},
		{"dotted keys", cfg("Insecure.DisableRateLimiting = true\n"), []int{1}},
		{"all false", cfg("[Insecure]\nDevWebServer = false\nDisableRateLimiting = false\n"), nil},
		{"section absent", cfg("[WebServer]\nHTTPPort = 6688\n"), nil},
	})
}
