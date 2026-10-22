package rules

import "testing"

func TestTracingUnencrypted(t *testing.T) {
	runRuleCases(t, tracingUnencrypted{}, []ruleCase{
		{"remote host:port", cfg("[Tracing]\nEnabled = true\nMode = 'unencrypted'\nCollectorTarget = 'otel.example.com:4317'\n"), []int{3}},
		{"remote URL form", cfg("[Tracing]\nEnabled = true\nMode = 'unencrypted'\nCollectorTarget = 'http://otel.example.com:4317'\n"), []int{3}},
		{"local collector", cfg("[Tracing]\nEnabled = true\nMode = 'unencrypted'\nCollectorTarget = 'localhost:4317'\n"), nil},
		{"compose service collector", cfg("[Tracing]\nEnabled = true\nMode = 'unencrypted'\nCollectorTarget = 'otel-collector:4317'\n"), nil},
		{"tls mode (default)", cfg("[Tracing]\nEnabled = true\nCollectorTarget = 'otel.example.com:4317'\nTLSCertPath = '/c.pem'\n"), nil},
		{"tracing disabled", cfg("[Tracing]\nMode = 'unencrypted'\nCollectorTarget = 'otel.example.com:4317'\n"), nil},
	})
}
