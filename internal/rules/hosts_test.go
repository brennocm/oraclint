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
