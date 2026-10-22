package rules

import "testing"

func TestWebCORSWildcard(t *testing.T) {
	runRuleCases(t, webCORSWildcard{}, []ruleCase{
		{"wildcard", cfg("[WebServer]\nAllowOrigins = '*'\n"), []int{2}},
		{"wildcard with spaces", cfg("[WebServer]\nAllowOrigins = ' * '\n"), []int{2}},
		{"wildcard inside list", cfg("[WebServer]\nAllowOrigins = 'https://ui.example.com,*'\n"), []int{2}},
		{"explicit origins", cfg("[WebServer]\nAllowOrigins = 'https://ui.example.com,https://ops.example.com'\n"), nil},
		{"subdomain pattern is not a wildcard origin", cfg("[WebServer]\nAllowOrigins = 'https://*.example.com'\n"), nil},
		{"default", cfg(""), nil},
	})
}
