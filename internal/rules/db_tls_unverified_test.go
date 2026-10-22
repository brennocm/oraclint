package rules

import "testing"

func TestDBTLSUnverified(t *testing.T) {
	runRuleCases(t, dbTLSUnverified{}, []ruleCase{
		{"no sslmode", sec("[Database]\nURL = 'postgresql://u:p@db.example.com/cl'\n"), []int{2}},
		{"prefer", sec("[Database]\nURL = 'postgresql://u:p@db.example.com/cl?sslmode=prefer'\n"), []int{2}},
		{"require without root cert", sec("[Database]\nURL = 'postgresql://u:p@db.example.com/cl?sslmode=require'\n"), []int{2}},
		{"require with root cert", sec("[Database]\nURL = 'postgresql://u:p@db.example.com/cl?sslmode=require&sslrootcert=/ca.pem'\n"), nil},
		{"verify-full", sec("[Database]\nURL = 'postgresql://u:p@db.example.com/cl?sslmode=verify-full'\n"), nil},
		{"disable is NS-DB-002", sec("[Database]\nURL = 'postgresql://u:p@db.example.com/cl?sslmode=disable'\n"), nil},
		{"internal host", sec("[Database]\nURL = 'postgresql://u:p@postgres/cl'\n"), nil},
	})
}
