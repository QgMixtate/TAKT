package winrminv

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Общие векторы с Rust-portable (C52.06): Parse по одному входу → тот же expected.json (эталон — Go); время сбора
// разделов не сравнивается. SURVEYSCAN_UPDATE_VECTORS=1 перезаписывает ожидание.
func TestRustParityVectors(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "agent-rs", "testdata", "winrm")
	got := map[string]any{}
	for _, name := range []string{"full", "errors", "fatal"} {
		raw, err := os.ReadFile(filepath.Join(dir, name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		secs, cands, err := Parse(raw, time.Now())
		if err != nil {
			got[name] = map[string]any{"error": true}
			continue
		}
		list := []map[string]any{}
		for _, s := range secs {
			list = append(list, map[string]any{"name": s.Name, "status": s.Status, "reason_code": s.Reason, "record_count": s.Count, "records": s.Records})
		}
		got[name] = map[string]any{"sections": list, "candidates": cands}
	}
	out, err := json.MarshalIndent(got, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')
	path := filepath.Join(dir, "expected.json")
	if os.Getenv("SURVEYSCAN_UPDATE_VECTORS") == "1" {
		if err = os.WriteFile(path, out, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(out, want) {
		t.Fatalf("winrm vectors differ from expected.json (Go is the reference)\n%s", out)
	}
}
