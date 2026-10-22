package rules

import "testing"

func TestDockerUIExposed(t *testing.T) {
	runRuleCases(t, dockerUIExposed{}, []ruleCase{
		{"all interfaces", compose("services:\n  chainlink:\n    image: smartcontract/chainlink:2.69.0\n    ports:\n      - \"6688:6688\"\n"), []int{5}},
		{"explicit 0.0.0.0 and https port", compose("services:\n  node:\n    image: smartcontract/chainlink:2.69.0\n    ports:\n      - 0.0.0.0:6688:6688\n      - 6689:6689\n"), []int{5, 6}},
		{"container port only", compose("services:\n  chainlink:\n    image: x/chainlink:1\n    ports: [6688]\n"), []int{4}},
		{"long syntax", compose("services:\n  chainlink:\n    image: smartcontract/chainlink:2.69.0\n    ports:\n      - target: 6688\n        published: \"6688\"\n"), []int{5}},
		{"specific private interface", compose("services:\n  chainlink:\n    image: smartcontract/chainlink:2.69.0\n    ports: ['10.0.0.5:6688:6688']\n"), []int{4}},
		{"loopback", compose("services:\n  chainlink:\n    image: smartcontract/chainlink:2.69.0\n    ports:\n      - 127.0.0.1:6688:6688\n      - '[::1]:6689:6689'\n"), nil},
		{"long syntax loopback", compose("services:\n  chainlink:\n    image: smartcontract/chainlink:2.69.0\n    ports:\n      - {target: 6688, host_ip: 127.0.0.1}\n"), nil},
		{"other service", compose("services:\n  grafana:\n    image: grafana/grafana:11.0.0\n    ports: ['6688:3000']\n"), nil},
		{"other container port", compose("services:\n  chainlink:\n    image: smartcontract/chainlink:2.69.0\n    ports: ['9090:9090']\n"), nil},
	})
}
