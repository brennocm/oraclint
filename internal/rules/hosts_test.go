package rules

import "testing"

func TestHosts(t *testing.T) {
	tests := []struct {
		host     string
		loopback bool
		internal bool
	}{
		{"localhost", true, true},
		{"api.localhost", true, true},
		{"127.0.0.2", true, true},
		{"::1", true, true},
		{"10.1.2.3", false, true},
		{"192.168.0.10", false, true},
		{"fd00::1", false, true},
		{"169.254.1.1", false, true},
		{"0.0.0.0", false, true},
		{"postgres", false, true},
		{"db.default.svc.cluster.local", false, true},
		{"host.docker.internal", false, true},
		{"", false, true},
		{"8.8.8.8", false, false},
		{"rpc.example.com", false, false},
		{"rpc.example.com.", false, false},
	}
	for _, tc := range tests {
		if got := isLoopback(tc.host); got != tc.loopback {
			t.Errorf("isLoopback(%q) = %v", tc.host, got)
		}
		if got := isInternalHost(tc.host); got != tc.internal {
			t.Errorf("isInternalHost(%q) = %v", tc.host, got)
		}
	}
}

func TestEndpointHost(t *testing.T) {
	tests := map[string]string{
		"otel.example.com:4317":         "otel.example.com",
		"https://otel.example.com:4317": "otel.example.com",
		"[::1]:4317":                    "::1",
		"collector":                     "collector",
		"collector/v1/traces":           "collector",
		"http://":                       "",
		"":                              "",
	}
	for in, want := range tests {
		if got := endpointHost(in); got != want {
			t.Errorf("endpointHost(%q) = %q, want %q", in, got, want)
		}
	}
}
