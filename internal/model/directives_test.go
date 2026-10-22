package model

import (
	"reflect"
	"testing"
)

func TestParseDirectives(t *testing.T) {
	src := `[WebServer.TLS]
HTTPSPort = 0 # oraclint:ignore NS-WEB-001 reason="TLS terminated at the load balancer"
# oraclint:ignore ns-web-002, NS-WEB-003 reason = "internal lab node"
SecureCookies = false
# oraclint:ignore NS-LOG-001
#oraclint:ignore reason="no id"
# oraclint:ignore NS-DB-001 reason="   "
# a normal comment mentioning oraclint
Key = "value # oraclint:ignore inside a string is still a match"
`
	// Known limitation (line 9): the scan is line based, so "#" inside a
	// quoted string looks like a comment. Such a directive has no reason
	// and is reported as invalid, so it can never suppress anything by
	// accident.
	got := ParseDirectives("c.toml", []byte(src))
	want := []Directive{
		{Loc: Location{File: "c.toml", Line: 2, Column: 15}, RuleIDs: []string{"NS-WEB-001"}, Reason: "TLS terminated at the load balancer"},
		{Loc: Location{File: "c.toml", Line: 3, Column: 1}, RuleIDs: []string{"NS-WEB-002", "NS-WEB-003"}, Reason: "internal lab node"},
		{Loc: Location{File: "c.toml", Line: 5, Column: 1}, RuleIDs: []string{"NS-LOG-001"}, Problem: `has no reason="..."; a justification is required`},
		{Loc: Location{File: "c.toml", Line: 6, Column: 1}, Reason: "no id", Problem: "names no rule ID"},
		{Loc: Location{File: "c.toml", Line: 7, Column: 1}, RuleIDs: []string{"NS-DB-001"}, Problem: `has no reason="..."; a justification is required`},
		{Loc: Location{File: "c.toml", Line: 9, Column: 14}, RuleIDs: []string{"INSIDE", "A", "STRING", "IS", "STILL", "A", "MATCH\""}, Problem: `has no reason="..."; a justification is required`},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	if ParseDirectives("e", nil) != nil {
		t.Error("no directives expected in empty input")
	}
}

func FuzzParseDirectives(f *testing.F) {
	f.Add([]byte(`# oraclint:ignore NS-WEB-001 reason="x"`))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, d := range ParseDirectives("f", data) {
			if d.Loc.Line < 1 || (d.Problem == "" && (len(d.RuleIDs) == 0 || d.Reason == "")) {
				t.Fatalf("invalid directive accepted: %+v", d)
			}
		}
	})
}
