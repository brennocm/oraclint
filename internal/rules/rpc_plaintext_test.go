package rules

import (
	"strings"
	"testing"
)

const rpcConfig = `[[EVM]]
ChainID = '1'

[[EVM.Nodes]]
Name = 'public-ws'
WSURL = 'ws://rpc.example.com/ws'
HTTPURL = 'https://rpc.example.com'

[[EVM.Nodes]]
Name = 'public-http'
WSURL = 'wss://rpc.example.com/ws'
HTTPURL = 'HTTP://rpc2.example.com'
HTTPURLExtraWrite = 'http://203.0.113.10:8545'

[[EVM.Nodes]]
Name = 'internal'
WSURL = 'ws://geth:8546'
HTTPURL = 'http://10.0.0.5:8545'
SendOnly = true

[[EVM]]
ChainID = '137'
Enabled = false

[[EVM.Nodes]]
Name = 'disabled-chain'
HTTPURL = 'http://polygon.example.com'
`

func TestRPCPlaintext(t *testing.T) {
	runRuleCases(t, rpcPlaintext{}, []ruleCase{
		{"mixed nodes", cfg(rpcConfig), []int{6, 12, 13}},
		{"no EVM section", cfg("[Log]\nLevel = 'info'\n"), nil},
		{"inline nodes", cfg("[[EVM]]\nChainID = '5'\nNodes = [{ Name = 'a', HTTPURL = 'http://a.example.com' }]\n"), []int{3}},
		{"unparsable URL ignored", cfg("[[EVM]]\nChainID = '5'\n[[EVM.Nodes]]\nName = 'a'\nHTTPURL = '::not a url'\n"), nil},
		{"localhost", cfg("[[EVM]]\nChainID = '1337'\n[[EVM.Nodes]]\nName = 'dev'\nHTTPURL = 'http://localhost:8545'\nWSURL = 'ws://127.0.0.1:8546'\n"), nil},
	})

	findings := rpcPlaintext{}.Check(configTarget(t, rpcConfig))
	if !strings.Contains(findings[0].Message, `chain "1" node "public-ws"`) || strings.Contains(findings[0].Message, "/ws") {
		t.Errorf("message should name chain and node but not the URL path: %q", findings[0].Message)
	}
}
