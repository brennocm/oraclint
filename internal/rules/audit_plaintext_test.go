package rules

import "testing"

func TestAuditPlaintext(t *testing.T) {
	runRuleCases(t, auditPlaintext{}, []ruleCase{
		{"remote http", cfg("[AuditLogger]\nEnabled = true\nForwardToUrl = 'http://audit.example.com/events'\n"), []int{3}},
		{"remote https", cfg("[AuditLogger]\nEnabled = true\nForwardToUrl = 'https://audit.example.com/events'\n"), nil},
		{"local http", cfg("[AuditLogger]\nEnabled = true\nForwardToUrl = 'http://localhost:9898'\n"), nil},
		{"disabled", cfg("[AuditLogger]\nForwardToUrl = 'http://audit.example.com'\n"), nil},
	})
}
