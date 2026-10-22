package rules

import (
	"strings"
	"testing"
)

func TestAuditHeaderSecret(t *testing.T) {
	runRuleCases(t, auditHeaderSecret{}, []ruleCase{
		{"authorization", cfg("[AuditLogger]\nHeaders = ['Authorization: Bearer abc123']\n"), []int{2}},
		{"multi-line array", cfg("[AuditLogger]\nHeaders = [\n  'X-Env: prod',\n  'X-Api-Key: k-123',\n]\n"), []int{4}},
		{"harmless headers", cfg("[AuditLogger]\nHeaders = ['X-Env: prod', 'Content-Type: application/json']\n"), nil},
		{"empty value", cfg("[AuditLogger]\nHeaders = ['Authorization:']\n"), nil},
		{"absent", cfg(""), nil},
	})
	f := auditHeaderSecret{}.Check(configTarget(t, "[AuditLogger]\nHeaders = ['Authorization: Bearer topsecret-xyz']\n"))
	if strings.Contains(f[0].Message, "topsecret") {
		t.Errorf("message leaks header value: %q", f[0].Message)
	}
}
