package rules

import "testing"

func TestEnvFileSecrets(t *testing.T) {
	runRuleCases(t, envFileSecrets{}, []ruleCase{
		{"secrets", dotenv("LOG_LEVEL=info\nCL_PASSWORD_KEYSTORE=abc\nPOSTGRES_PASSWORD=def\n"), []int{2, 3}},
		{"empty values", dotenv("CL_PASSWORD_KEYSTORE=\n"), nil},
		{"unrelated", dotenv("CL_DEV=true\nTZ=UTC\n"), nil},
	})
}
