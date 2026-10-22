package rules

import (
	"sort"
	"strings"
)

// All returns every built-in rule, sorted by ID.
//
// The list is explicit on purpose (no init() self-registration): reading this
// function tells you exactly which rules ship, and adding a rule is a visible
// one-line change in review.
func All() []Rule {
	all := []Rule{
		insecureFlags{},
		ksFastScrypt{},
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Metadata().ID < all[j].Metadata().ID })
	return all
}

// ByID returns the rule with the given ID (case-insensitive).
func ByID(id string) (Rule, bool) {
	for _, r := range All() {
		if strings.EqualFold(r.Metadata().ID, id) {
			return r, true
		}
	}
	return nil, false
}
