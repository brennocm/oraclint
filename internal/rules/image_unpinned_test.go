package rules

import "testing"

func TestImageUnpinned(t *testing.T) {
	runRuleCases(t, imageUnpinned{}, []ruleCase{
		{"latest and none", compose("services:\n  a:\n    image: smartcontract/chainlink:latest\n  b:\n    image: postgres\n  c:\n    image: postgres:16\n"), []int{3, 5}},
		{"digest without tag", compose("services:\n  a:\n    image: postgres@sha256:0123\n"), nil},
		{"interpolated", compose("services:\n  a:\n    image: smartcontract/chainlink:${CL_VERSION}\n"), nil},
		{"build only", compose("services:\n  a:\n    build: .\n"), nil},
		{"k8s containers and init containers", k8s("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: node}\nspec:\n  template:\n    spec:\n      initContainers:\n      - name: init\n        image: busybox\n      containers:\n      - name: node\n        image: smartcontract/chainlink:2.69.0\n"), []int{9}},
	})
}
