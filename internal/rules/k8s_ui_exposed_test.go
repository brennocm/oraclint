package rules

import (
	"testing"

	"github.com/brennocm/oraclint/internal/model"
)

func TestK8sUIExposed(t *testing.T) {
	svc := func(typ, ports string) func(t *testing.T) *model.Target {
		return k8s("apiVersion: v1\nkind: Service\nmetadata: {name: chainlink}\nspec:\n  type: " + typ + "\n  ports:\n" + ports)
	}
	runRuleCases(t, k8sUIExposed{}, []ruleCase{
		{"load balancer", svc("LoadBalancer", "  - port: 6688\n"), []int{7}},
		{"node port via targetPort", svc("NodePort", "  - port: 80\n    targetPort: 6688\n"), []int{7}},
		{"https port", svc("LoadBalancer", "  - port: 443\n    targetPort: 6689\n"), []int{7}},
		{"named targetPort", svc("LoadBalancer", "  - port: 443\n    targetPort: http\n"), nil},
		{"cluster ip", svc("ClusterIP", "  - port: 6688\n"), nil},
		{"other port", svc("LoadBalancer", "  - port: 30303\n"), nil},
	})
}
