package rules

import (
	"strings"
	"testing"
)

func TestDBTLSDisabled(t *testing.T) {
	runRuleCases(t, dbTLSDisabled{}, []ruleCase{
		{"remote disable", sec("[Database]\nURL = 'postgresql://u:p@db.example.com:5432/cl?sslmode=disable'\n"), []int{2}},
		{"remote allow, backup too", sec("[Database]\nURL = 'postgres://u:p@db.example.com/cl?sslmode=allow'\nBackupURL = 'postgres://u:p@203.0.113.7/cl?sslmode=DISABLE'\n"), []int{2, 3}},
		{"remote verify-full", sec("[Database]\nURL = 'postgresql://u:p@db.example.com/cl?sslmode=verify-full'\n"), nil},
		{"remote require", sec("[Database]\nURL = 'postgresql://u:p@db.example.com/cl?sslmode=require'\n"), nil},
		{"remote without sslmode (driver default prefer)", sec("[Database]\nURL = 'postgresql://u:p@db.example.com/cl'\n"), nil},
		{"localhost disable", sec("[Database]\nURL = 'postgresql://u:p@localhost:5432/cl?sslmode=disable'\n"), nil},
		{"compose service name", sec("[Database]\nURL = 'postgresql://u:p@postgres:5432/cl?sslmode=disable'\n"), nil},
		{"unix socket", sec("[Database]\nURL = 'postgresql://u:p@/cl?host=/var/run/postgresql&sslmode=disable'\n"), nil},
		{"host in query", sec("[Database]\nURL = 'postgresql://u:p@/cl?host=db.example.com&sslmode=disable'\n"), []int{2}},
		{"not a postgres URL", sec("[Database]\nURL = 'mysql://db.example.com/?sslmode=disable'\n"), nil},
		{"absent", sec("[Password]\nKeystore = 'x'\n"), nil},
	})

	f := dbTLSDisabled{}.Check(secretsTarget(t, "[Database]\nURL = 'postgresql://admin:pa55word-xyz@db.example.com/cl?sslmode=disable'\n"))
	if strings.Contains(f[0].Message, "pa55word-xyz") || strings.Contains(f[0].Message, "admin") {
		t.Errorf("message leaks credentials: %q", f[0].Message)
	}
}
