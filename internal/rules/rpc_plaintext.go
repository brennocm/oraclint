package rules

import (
	"fmt"
	"strings"

	"github.com/brennocm/oraclint/internal/model"
)

// rpcPlaintext flags EVM RPC endpoints reached over http:// or ws:// on a
// public network. A network attacker can then read and alter the chain data
// the node reports on and the transactions it broadcasts.
type rpcPlaintext struct{}

var rpcURLKeys = []string{"HTTPURL", "WSURL", "HTTPURLExtraWrite"}

func (rpcPlaintext) Metadata() Metadata {
	return Metadata{
		ID:          "NS-RPC-001",
		Title:       "RPC endpoint uses unencrypted transport",
		Severity:    SeverityHigh,
		Targets:     []model.Kind{model.KindConfig},
		Status:      Stable,
		Remediation: "Use https:// and wss:// endpoints, or keep the RPC node on a private network.",
		References:  []string{refConfig + "#evmnodes", refBestPractic},
		CWE:         []string{"CWE-319"},
	}
}

func (r rpcPlaintext) Check(t *model.Target) []Finding {
	var out []Finding
	for _, chain := range t.TOML.Root.Get("EVM").Items() {
		if !t.TOML.GetIn(chain, "Enabled", "EVM.Enabled").IsTrue() {
			continue // a disabled chain never connects
		}
		chainID := scalarText(chain.Get("ChainID"))
		for _, node := range chain.Get("Nodes").Items() {
			for _, key := range rpcURLKeys {
				v := node.Get(key)
				if v == nil {
					continue
				}
				raw, _ := v.Scalar.(string)
				u, ok := parseURL(raw)
				if !ok {
					continue
				}
				scheme := strings.ToLower(u.Scheme)
				if (scheme != "http" && scheme != "ws") || isInternalHost(u.Hostname()) {
					continue
				}
				out = append(out, newFinding(r.Metadata(), v.Loc,
					"EVM chain %s node %s: %s uses unencrypted %s:// to %s",
					chainID, scalarText(node.Get("Name")), key, scheme, u.Hostname()))
			}
		}
	}
	return out
}

// scalarText renders a scalar for messages, or "?" when missing. It is only
// used for identifiers (chain IDs, node names), never for secret values.
func scalarText(v *model.Value) string {
	if v == nil || v.Kind != model.ScalarValue {
		return "?"
	}
	if s, ok := v.Scalar.(string); ok {
		return fmt.Sprintf("%q", s)
	}
	return fmt.Sprint(v.Scalar)
}
