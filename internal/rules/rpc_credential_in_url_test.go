package rules

import (
	"strings"
	"testing"
)

func evmNode(url string) string {
	return "[[EVM]]\nChainID = '1'\n[[EVM.Nodes]]\nName = 'n'\nHTTPURL = '" + url + "'\n"
}

func TestRPCCredentialInURL(t *testing.T) {
	runRuleCases(t, rpcCredentialInURL{}, []ruleCase{
		{"infura key in path", cfg(evmNode("https://mainnet.infura.io/v3/0123456789abcdef0123456789abcdef")), []int{5}},
		{"alchemy key", cfg(evmNode("https://eth-mainnet.g.alchemy.com/v2/AbCdEfGhIjKlMnOp1234567890")), []int{5}},
		{"quicknode token", cfg(evmNode("https://x.quiknode.pro/0123456789abcdef0123456789abcdef01234567/")), []int{5}},
		{"query apikey", cfg(evmNode("https://rpc.example.com/?apikey=abc")), []int{5}},
		{"basic auth", cfg(evmNode("https://user:pass@rpc.example.com")), []int{5}},
		{"plain public URL", cfg(evmNode("https://rpc.example.com/eth")), nil},
		{"short path segments", cfg(evmNode("https://rpc.example.com/v1/mainnet")), nil},
		{"long segment without digits", cfg(evmNode("https://rpc.example.com/ethereum-mainnet-archive-node")), nil},
		{"disabled chain still flagged", cfg("[[EVM]]\nChainID = '5'\nEnabled = false\n[[EVM.Nodes]]\nName = 'n'\nWSURL = 'wss://rpc.example.com/ws/0123456789abcdef0123456789abcdef'\n"), []int{6}},
	})
	f := rpcCredentialInURL{}.Check(configTarget(t, evmNode("https://mainnet.infura.io/v3/0123456789abcdef0123456789abcdef")))
	if strings.Contains(f[0].Message, "0123456789abcdef") {
		t.Errorf("message leaks the key: %q", f[0].Message)
	}
}
