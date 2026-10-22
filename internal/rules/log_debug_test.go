package rules

import "testing"

func TestLogDebug(t *testing.T) {
	runRuleCases(t, logDebug{}, []ruleCase{
		{"debug", cfg("[Log]\nLevel = 'debug'\n"), []int{2}},
		{"uppercase", cfg("Log.Level = 'DEBUG'\n"), []int{1}},
		{"info", cfg("[Log]\nLevel = 'info'\n"), nil},
		{"default", cfg(""), nil},
	})
}
