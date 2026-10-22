package rules

import "testing"

func TestParseShortPort(t *testing.T) {
	tests := []struct {
		spec     string
		hostIP   string
		from, to int
		ok       bool
	}{
		{"6688", "", 6688, 6688, true},
		{"6688:6688", "", 6688, 6688, true},
		{"8080:6688/tcp", "", 6688, 6688, true},
		{"127.0.0.1:6688:6688", "127.0.0.1", 6688, 6688, true},
		{"0.0.0.0:16688:6688", "0.0.0.0", 6688, 6688, true},
		{"[::1]:6688:6688", "::1", 6688, 6688, true},
		{"::1:6688:6688", "::1", 6688, 6688, true},
		{"6680-6690:6680-6690", "", 6680, 6690, true},
		{"6690-6680", "", 0, 0, false},
		{"[::1:6688", "", 0, 0, false},
		{"http", "", 0, 0, false},
	}
	for _, tc := range tests {
		pp, ok := parseShortPort(tc.spec)
		if ok != tc.ok || (ok && (pp.HostIP != tc.hostIP || pp.ContainerFrom != tc.from || pp.ContainerTo != tc.to)) {
			t.Errorf("parseShortPort(%q) = %+v, %v", tc.spec, pp, ok)
		}
	}
}

func TestImageRefs(t *testing.T) {
	tests := []struct {
		ref, name, tag string
		digest         bool
	}{
		{"smartcontract/chainlink:2.69.0", "chainlink", "2.69.0", false},
		{"smartcontract/chainlink", "chainlink", "", false},
		{"postgres:16-alpine", "postgres", "16-alpine", false},
		{"registry.local:5000/team/postgres", "postgres", "", false},
		{"registry.local:5000/team/postgres:15", "postgres", "15", false},
		{"public.ecr.aws/chainlink/chainlink:2.69.0@sha256:abc", "chainlink", "2.69.0", true},
		{"busybox@sha256:abc", "busybox", "", true},
	}
	for _, tc := range tests {
		tag, digest := imageTag(tc.ref)
		if imageName(tc.ref) != tc.name || tag != tc.tag || digest != tc.digest {
			t.Errorf("%q: name=%q tag=%q digest=%v", tc.ref, imageName(tc.ref), tag, digest)
		}
	}
}
