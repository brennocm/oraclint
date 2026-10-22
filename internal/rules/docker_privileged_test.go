package rules

import "testing"

func TestDockerPrivileged(t *testing.T) {
	runRuleCases(t, dockerPrivileged{}, []ruleCase{
		{"privileged", compose("services:\n  n:\n    image: a:1\n    privileged: true\n"), []int{4}},
		{"host network and pid", compose("services:\n  n:\n    image: a:1\n    network_mode: host\n    pid: host\n"), []int{4, 5}},
		{"caps", compose("services:\n  n:\n    image: a:1\n    cap_add:\n      - NET_BIND_SERVICE\n      - CAP_SYS_ADMIN\n      - all\n"), []int{6, 7}},
		{"privileged false", compose("services:\n  n:\n    image: a:1\n    privileged: false\n    network_mode: bridge\n"), nil},
		{"no services", compose("version: '3'\n"), nil},
	})
}
