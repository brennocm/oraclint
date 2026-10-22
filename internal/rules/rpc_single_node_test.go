package rules

import "testing"

func TestRPCSingleNode(t *testing.T) {
	runRuleCases(t, rpcSingleNode{}, []ruleCase{
		{"one primary", cfg("[[EVM]]\nChainID = '1'\n[[EVM.Nodes]]\nName = 'only'\nHTTPURL = 'https://a.example'\n"), []int{3}},
		{"one primary plus send-only", cfg("[[EVM]]\nChainID = '1'\n[[EVM.Nodes]]\nName = 'p'\nHTTPURL = 'https://a.example'\n[[EVM.Nodes]]\nName = 's'\nHTTPURL = 'https://b.example'\nSendOnly = true\n"), []int{3}},
		{"two primaries", cfg("[[EVM]]\nChainID = '1'\n[[EVM.Nodes]]\nName = 'a'\nHTTPURL = 'https://a.example'\n[[EVM.Nodes]]\nName = 'b'\nHTTPURL = 'https://b.example'\n"), nil},
		{"load balanced", cfg("[[EVM]]\nChainID = '1'\n[[EVM.Nodes]]\nName = 'lb'\nHTTPURL = 'https://lb.example'\nIsLoadBalancedRPC = true\n"), nil},
		{"disabled chain", cfg("[[EVM]]\nChainID = '1'\nEnabled = false\n[[EVM.Nodes]]\nName = 'only'\nHTTPURL = 'https://a.example'\n"), nil},
		{"two chains, one single", cfg("[[EVM]]\nChainID = '1'\n[[EVM.Nodes]]\nName = 'a'\n[[EVM.Nodes]]\nName = 'b'\n[[EVM]]\nChainID = '10'\n[[EVM.Nodes]]\nName = 'c'\n"), []int{9}},
		{"no nodes", cfg("[[EVM]]\nChainID = '1'\n"), nil},
	})
}
