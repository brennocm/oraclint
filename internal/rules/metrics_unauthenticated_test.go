package rules

import "testing"

func TestMetricsUnauthenticated(t *testing.T) {
	runRuleCases(t, metricsUnauthenticated{}, []ruleCase{
		{"no token", sec("[Password]\nKeystore = 'x'\n"), []int{0}},
		{"empty token", sec("[Prometheus]\nAuthToken = ''\n"), []int{0}},
		{"token set", sec("[Prometheus]\nAuthToken = 'prom-token'\n"), nil},
	})
}
