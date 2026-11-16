package wire

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Эталоны канонической формы общие с Rust-агентом (agent-rs/testdata/canonical, C52.02): обе реализации обязаны
// давать побайтно одинаковый результат.
func TestCanonicalVectorsSharedWithRust(t *testing.T) {
	files, _ := filepath.Glob("../../../agent-rs/testdata/canonical/*.json")
	if len(files) < 50 {
		t.Fatal("shared vectors missing", len(files))
	}
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		want, err := os.ReadFile(strings.TrimSuffix(f, ".json") + ".canon")
		if err != nil {
			t.Fatal(err)
		}
		got, err := Canonical(raw)
		if err != nil || string(got) != string(want) {
			t.Fatalf("%s: %v\n%s\n%s", f, err, got, want)
		}
	}
}
