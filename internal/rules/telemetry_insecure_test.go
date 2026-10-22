package rules

import "testing"

func TestTelemetryInsecure(t *testing.T) {
	runRuleCases(t, telemetryInsecure{}, []ruleCase{
		{"insecure remote", cfg("[Telemetry]\nEnabled = true\nEndpoint = 'telemetry.example.com:4317'\nInsecureConnection = true\n"), []int{4}},
		{"insecure local", cfg("[Telemetry]\nEnabled = true\nEndpoint = 'localhost:4317'\nInsecureConnection = true\n"), nil},
		{"insecure but disabled", cfg("[Telemetry]\nEndpoint = 'telemetry.example.com:4317'\nInsecureConnection = true\n"), nil},
		{"tls", cfg("[Telemetry]\nEnabled = true\nEndpoint = 'telemetry.example.com:4317'\nCACertFile = '/ca.pem'\n"), nil},
		{"chip ingress insecure remote", cfg("[Telemetry]\nChipIngressEndpoint = 'chip.example.com:443'\nChipIngressInsecureConnection = true\n"), []int{3}},
		{"chip ingress insecure without endpoint", cfg("[Telemetry]\nChipIngressInsecureConnection = true\n"), nil},
		{"both", cfg("[Telemetry]\nEnabled = true\nEndpoint = 'a.example.com:1'\nInsecureConnection = true\nChipIngressEndpoint = 'b.example.com:2'\nChipIngressInsecureConnection = true\n"), []int{4, 6}},
	})
}
