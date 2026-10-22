package rules

import (
	"strings"
	"testing"

	"github.com/brennocm/oraclint/internal/model"
)

func TestEnvLiteralSecret(t *testing.T) {
	runRuleCases(t, envLiteralSecret{}, []ruleCase{
		{"compose map", compose("services:\n  n:\n    environment:\n      CL_DATABASE_URL: postgresql://u:p@db/x\n      LOG_LEVEL: info\n"), []int{4}},
		{"compose list", compose("services:\n  db:\n    environment:\n      - POSTGRES_PASSWORD=example\n"), []int{4}},
		{"compose interpolation", compose("services:\n  n:\n    environment:\n      CL_PASSWORD_KEYSTORE: ${KEYSTORE_PASSWORD}\n      CL_DATABASE_URL: postgresql://u:${PG_PASS}@db/x\n"), nil},
		{"compose pass-through", compose("services:\n  n:\n    environment:\n      - CL_PASSWORD_KEYSTORE\n"), nil},
		{"k8s literal", k8s("apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: n\n    env:\n    - name: CL_PASSWORD_KEYSTORE\n      value: example\n"), []int{7}},
		{"k8s secretKeyRef", k8s("apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: n\n    env:\n    - name: CL_PASSWORD_KEYSTORE\n      valueFrom:\n        secretKeyRef: {name: s, key: k}\n"), nil},
	})
	f := envLiteralSecret{}.Check(yamlTarget(t, model.KindCompose, "services:\n  n:\n    environment:\n      CL_PASSWORD_KEYSTORE: super-secret-literal\n"))
	if len(f) != 1 || strings.Contains(f[0].Message, "super-secret-literal") {
		t.Errorf("expected one finding without the value, got %+v", f)
	}
}
