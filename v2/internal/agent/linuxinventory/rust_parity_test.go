package linuxinventory

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Общие векторы с Rust-агентом (C52.02): Go и Rust (agent-rs/tests/linux12.rs) сравнивают вывод парсеров с одним
// expected.json. SURVEYSCAN_UPDATE_VECTORS=1 перезаписывает ожидание из Go (эталон — Go-реализация).
func TestRustParityVectors(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "agent-rs", "testdata", "linux12")
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	var dmi map[string]string
	if err := json.Unmarshal([]byte(read("dmi.json")), &dmi); err != nil {
		t.Fatal(err)
	}
	got := map[string]any{
		"hardware": Hardware(read("cpuinfo"), read("meminfo")),
		"packages": Packages(read("dpkg")),
		"accounts": Accounts(read("passwd"), read("group")),
		"mounts":   Mounts(read("mountinfo")),
		"tcp":      Sockets("tcp", read("tcp"), false),
		"tcp6":     Sockets("tcp", read("tcp6"), true),
		"udp":      Sockets("udp", read("udp"), false),
		"routes":   Routes(read("route")),
		"rpm":      RPMPackages(read("rpm")),
		"apk":      APKPackages(read("apk")),
		"services": SystemdServices(read("units"), read("unitfiles")),
		"dmi":      DMI(dmi),
	}
	raw, err := json.MarshalIndent(got, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	path := filepath.Join(dir, "expected.json")
	if os.Getenv("SURVEYSCAN_UPDATE_VECTORS") == "1" {
		if err = os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if want := read("expected.json"); !bytes.Equal(raw, []byte(want)) {
		t.Fatalf("linux12 vectors differ from expected.json (Go is the reference)\n%s", raw)
	}
}
