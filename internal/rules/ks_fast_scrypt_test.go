package rules

import "testing"

func TestKSFastScrypt(t *testing.T) {
	runRuleCases(t, ksFastScrypt{}, []ruleCase{
		{"enabled", cfg("Log.Level = 'info'\nInsecureFastScrypt = true\n"), []int{2}},
		{"disabled explicitly", cfg("InsecureFastScrypt = false\n"), nil},
		{"absent uses default false", cfg("[Log]\nLevel = 'info'\n"), nil},
		{"wrong type is ignored", cfg("InsecureFastScrypt = 'true'\n"), nil},
	})
}
