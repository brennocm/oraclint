package rules

import "testing"

const k8sPrivilegedPod = `apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: chainlink
spec:
  template:
    spec:
      hostNetwork: true
      hostPID: false
      containers:
      - name: node
        image: smartcontract/chainlink:2.69.0
        securityContext:
          privileged: true
`

func TestK8sPrivileged(t *testing.T) {
	runRuleCases(t, k8sPrivileged{}, []ruleCase{
		{"host network and privileged container", k8s(k8sPrivilegedPod), []int{8, 14}},
		{"clean pod", k8s("apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  containers:\n  - name: n\n    securityContext: {privileged: false}\n"), nil},
		{"not a workload", k8s("apiVersion: v1\nkind: Service\nspec:\n  hostNetwork: true\n"), nil},
		{"hostPath docker socket", k8s("apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  volumes:\n  - name: sock\n    hostPath: {path: /var/run/docker.sock}\n  - name: data\n    hostPath: {path: /srv/chainlink}\n  containers: [{name: n}]\n"), []int{7}},
		{"inside a List", k8s("apiVersion: v1\nkind: List\nitems:\n- apiVersion: v1\n  kind: Pod\n  metadata: {name: p}\n  spec:\n    hostPID: true\n    containers: [{name: n}]\n"), []int{8}},
	})
}
