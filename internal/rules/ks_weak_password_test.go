package rules

import (
	"strings"
	"testing"
)

func TestKSWeakPassword(t *testing.T) {
	runRuleCases(t, ksWeakPassword{}, []ruleCase{
		{"short keystore", sec("[Password]\nKeystore = 'password123'\n"), []int{2}},
		{"exactly 16", sec("[Password]\nKeystore = 'abcdefghijklmnop'\n"), nil},
		{"15 characters", sec("[Password]\nKeystore = 'abcdefghijklmno'\n"), []int{2}},
		{"trailing whitespace", sec("[Password]\nKeystore = 'abcdefghijklmnopqrstu '\n"), []int{2}},
		{"short VRF too", sec("[Password]\nKeystore = 'a-very-long-keystore-password'\nVRF = 'vrf'\n"), []int{3}},
		{"absent", sec("[Database]\nURL = 'postgresql://u:p@h/x'\n"), nil},
		{"dotenv", dotenv("CL_PASSWORD_KEYSTORE=short\nCL_PASSWORD_VRF=long-enough-vrf-password\n"), []int{1}},
		{"compose literal", compose("services:\n  node:\n    environment:\n      - CL_PASSWORD_KEYSTORE=short\n"), []int{4}},
		{"compose interpolated", compose("services:\n  node:\n    environment:\n      - CL_PASSWORD_KEYSTORE=${KS}\n"), nil},
		{"k8s secretKeyRef", k8s("apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: n\n    env:\n    - name: CL_PASSWORD_KEYSTORE\n      valueFrom: {secretKeyRef: {name: s, key: k}}\n"), nil},
	})
	f := ksWeakPassword{}.Check(secretsTarget(t, "[Password]\nKeystore = 'hunter2'\n"))
	if strings.Contains(f[0].Message, "hunter2") || strings.Contains(f[0].Message, "7") {
		t.Errorf("message leaks the password or its length: %q", f[0].Message)
	}
}
