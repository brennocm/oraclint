package rules

import "testing"

func TestDockerRootUser(t *testing.T) {
	runRuleCases(t, dockerRootUser{}, []ruleCase{
		{"root", compose("services:\n  chainlink:\n    image: smartcontract/chainlink:2.69.0\n    user: root\n"), []int{4}},
		{"uid 0 with group", compose("services:\n  chainlink:\n    image: smartcontract/chainlink:2.69.0\n    user: \"0:14933\"\n"), []int{4}},
		{"official uid", compose("services:\n  chainlink:\n    image: smartcontract/chainlink:2.69.0\n    user: \"14933:14933\"\n"), nil},
		{"no user (image default)", compose("services:\n  chainlink:\n    image: smartcontract/chainlink:2.69.0\n"), nil},
		{"root in another service", compose("services:\n  db:\n    image: postgres:16\n    user: root\n"), nil},
		{"uid starting with 0", compose("services:\n  chainlink:\n    image: smartcontract/chainlink:2.69.0\n    user: \"01000\"\n"), nil},
	})
}
