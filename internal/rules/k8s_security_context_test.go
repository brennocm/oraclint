package rules

import (
	"strings"
	"testing"

	"github.com/brennocm/oraclint/internal/model"
)

const hardenedContainer = `    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      readOnlyRootFilesystem: true
`

func TestK8sSecurityContext(t *testing.T) {
	runRuleCases(t, k8sSecurityContext{}, []ruleCase{
		{"nothing set", k8s("apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  containers:\n  - name: n\n    image: a:1\n"), []int{6}},
		{"hardened", k8s("apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  containers:\n  - name: n\n" + hardenedContainer), nil},
		{"runAsNonRoot from pod", k8s("apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  securityContext: {runAsNonRoot: true}\n  containers:\n  - name: n\n    securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true}\n"), nil},
		{"container overrides pod", k8s("apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  securityContext: {runAsNonRoot: true}\n  containers:\n  - name: n\n    securityContext: {runAsNonRoot: false, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true}\n"), []int{7}},
		{"escalation true", k8s("apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  containers:\n  - name: n\n    securityContext: {allowPrivilegeEscalation: true, runAsNonRoot: true, readOnlyRootFilesystem: true}\n"), []int{6}},
	})

	f := k8sSecurityContext{}.Check(yamlTarget(t, model.KindK8s, "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  containers:\n  - name: n\n    securityContext: {runAsNonRoot: true}\n"))
	if len(f) != 1 || !strings.Contains(f[0].Message, "allowPrivilegeEscalation: false, readOnlyRootFilesystem: true") || strings.Contains(f[0].Message, "runAsNonRoot") {
		t.Errorf("message should list exactly the missing settings: %+v", f)
	}
}
