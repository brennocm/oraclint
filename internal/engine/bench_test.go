package engine

import (
	"path/filepath"
	"testing"

	"github.com/brennocm/oraclint/internal/loader"
	"github.com/brennocm/oraclint/internal/rules"
)

// BenchmarkScan measures the full pipeline (discovery, parsing, every rule,
// suppressions, redaction) on examples/insecure-node.
func BenchmarkScan(b *testing.B) {
	dir := filepath.Join("..", "..", "examples", "insecure-node")
	all := rules.All()
	b.ReportAllocs()
	for b.Loop() {
		res, err := loader.Load([]string{dir}, loader.Options{})
		if err != nil {
			b.Fatal(err)
		}
		if len(Run(res.Targets, res.Problems, all, Options{Experimental: true})) == 0 {
			b.Fatal("expected findings")
		}
	}
}
