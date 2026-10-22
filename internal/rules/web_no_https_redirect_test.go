package rules

import "testing"

func TestWebNoHTTPSRedirect(t *testing.T) {
	runRuleCases(t, webNoHTTPSRedirect{}, []ruleCase{
		{"cert configured, no redirect", cfg("[WebServer.TLS]\nCertPath = '/tls/server.crt'\nKeyPath = '/tls/server.key'\n"), []int{1}},
		{"explicit https port, redirect false", cfg("[WebServer.TLS]\nHTTPSPort = 6689\nForceRedirect = false\n"), []int{3}},
		{"redirect on", cfg("[WebServer.TLS]\nCertPath = '/tls/server.crt'\nForceRedirect = true\n"), nil},
		{"plaintext listener off", cfg("[WebServer]\nHTTPPort = 0\n[WebServer.TLS]\nCertPath = '/tls/server.crt'\n"), nil},
		{"https disabled", cfg("[WebServer.TLS]\nHTTPSPort = 0\n"), nil},
		{"tls not configured", cfg("[WebServer]\nHTTPPort = 6688\n"), nil},
	})
}
