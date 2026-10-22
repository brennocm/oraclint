package rules

import "testing"

func TestDBSimplePasswords(t *testing.T) {
	runRuleCases(t, dbSimplePasswords{}, []ruleCase{
		{"secrets true", sec("[Database]\nAllowSimplePasswords = true\n"), []int{2}},
		{"secrets false", sec("[Database]\nAllowSimplePasswords = false\n"), nil},
		{"secrets default", sec("[Database]\nURL = 'postgresql://u:p@h/x'\n"), nil},
		{"dotenv true", dotenv("CL_DATABASE_ALLOW_SIMPLE_PASSWORDS=true\n"), []int{1}},
		{"dotenv TRUE", dotenv("CL_DATABASE_ALLOW_SIMPLE_PASSWORDS=TRUE\n"), []int{1}},
		{"dotenv 1 is not true for the node", dotenv("CL_DATABASE_ALLOW_SIMPLE_PASSWORDS=1\n"), nil},
		{"compose", compose("services:\n  node:\n    environment:\n      CL_DATABASE_ALLOW_SIMPLE_PASSWORDS: 'true'\n"), []int{4}},
		{"compose interpolated", compose("services:\n  node:\n    environment:\n      CL_DATABASE_ALLOW_SIMPLE_PASSWORDS: ${ALLOW}\n"), nil},
		{"k8s", k8s("apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: n\n    env:\n    - name: CL_DATABASE_ALLOW_SIMPLE_PASSWORDS\n      value: \"true\"\n"), []int{7}},
	})
}
