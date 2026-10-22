package rules

import "testing"

func TestWebHTTPSDisabled(t *testing.T) {
	runRuleCases(t, webHTTPSDisabled{}, []ruleCase{
		{"https off, http default", cfg("[WebServer.TLS]\nHTTPSPort = 0\n"), []int{2}},
		{"https off, http explicit", cfg("[WebServer]\nHTTPPort = 8080\n[WebServer.TLS]\nHTTPSPort = 0\n"), []int{4}},
		{"both listeners off", cfg("[WebServer]\nHTTPPort = 0\n[WebServer.TLS]\nHTTPSPort = 0\n"), nil},
		{"https default port", cfg("[WebServer]\nHTTPPort = 6688\n"), nil},
		{"https custom port", cfg("[WebServer.TLS]\nHTTPSPort = 443\n"), nil},
		{"empty config", cfg(""), nil},
	})
}
