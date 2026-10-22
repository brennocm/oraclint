package rules

import (
	"strings"

	"github.com/brennocm/oraclint/internal/model"
)

// rpcSingleNode flags a chain with only one primary (non send-only) RPC node
// that is not marked as load-balanced. The node then depends on one endpoint
// for every observation it makes on that chain: an outage stops it, and a
// misbehaving or compromised provider cannot be detected by comparing heads.
type rpcSingleNode struct{}

func (rpcSingleNode) Metadata() Metadata {
	return Metadata{
		ID:          "NS-RPC-003",
		Title:       "Single primary RPC node for chain",
		Severity:    SeverityLow,
		Targets:     []model.Kind{model.KindConfig},
		Status:      Stable,
		Remediation: "Configure at least two primary [[EVM.Nodes]], ideally from different providers, or set IsLoadBalancedRPC = true if the URL fronts several RPC nodes.",
		References:  []string{refConfig + "#evmnodes", refBestPractic},
		CWE:         []string{"CWE-1357"},
	}
}

func (r rpcSingleNode) Check(t *model.Target) []Finding {
	var out []Finding
	for _, chain := range t.TOML.Root.Get("EVM").Items() {
		if !t.TOML.GetIn(chain, "Enabled", "EVM.Enabled").IsTrue() {
			continue
		}
		var primaries []*model.Value
		for _, node := range chain.Get("Nodes").Items() {
			if !t.TOML.GetIn(node, "SendOnly", "EVM.Nodes.SendOnly").IsTrue() {
				primaries = append(primaries, node)
			}
		}
		if len(primaries) != 1 {
			continue
		}
		node := primaries[0]
		if t.TOML.GetIn(node, "IsLoadBalancedRPC", "EVM.Nodes.IsLoadBalancedRPC").IsTrue() {
			continue
		}
		out = append(out, newFinding(r.Metadata(), node.Loc,
			"EVM chain %s relies on a single primary RPC node (%s)", scalarText(chain.Get("ChainID")), scalarText(node.Get("Name"))))
	}
	return out
}

func splitPath(p string) []string {
	return strings.Split(strings.Trim(p, "/"), "/")
}
