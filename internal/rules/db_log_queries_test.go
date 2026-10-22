package rules

import "testing"

func TestDBLogQueries(t *testing.T) {
	runRuleCases(t, dbLogQueries{}, []ruleCase{
		{"enabled", cfg("[Database]\nLogQueries = true\n"), []int{2}},
		{"disabled", cfg("[Database]\nLogQueries = false\n"), nil},
		{"default", cfg("[Database]\nMaxIdleConns = 10\n"), nil},
	})
}
