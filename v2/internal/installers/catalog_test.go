package installers

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type entry struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Mode   int    `json:"mode"`
}

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// release собирает каталог установленного выпуска: payload + release-manifest.json/.sig.
func release(t *testing.T, files map[string][]byte, idx []File) (string, ed25519.PrivateKey, []byte) {
	t.Helper()
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	os.MkdirAll(filepath.Join(dir, "installers"), 0o755)
	ib, _ := json.Marshal(index{Format: "surveyscan-installers-v1", Files: idx})
	files["index.json"] = ib
	m := manifest{Format: "surveyscan-release-v1", Version: "1.2.3"}
	all := map[string]entry{}
	for n, b := range files {
		os.WriteFile(filepath.Join(dir, "installers", n), b, 0o644)
		all["installers/"+n] = entry{sum(b), int64(len(b)), 0o644}
	}
	raw, _ := json.Marshal(map[string]any{"format": m.Format, "version": m.Version, "files": all})
	os.WriteFile(filepath.Join(dir, "release-manifest.json"), raw, 0o644)
	os.WriteFile(filepath.Join(dir, "release-manifest.sig"), ed25519.Sign(priv, raw), 0o644)
	return dir, priv, pubPEM
}

func TestCatalogSignedReleaseFiles(t *testing.T) {
	msi := []byte("MSI bytes")
	deb := []byte("deb bytes")
	dir, _, pub := release(t, map[string][]byte{"surveyscan-agent_1.2.3_windows_x64.msi": msi, "surveyscan-agent_1.2.3-1_amd64.deb": deb},
		[]File{{Name: "surveyscan-agent_1.2.3-1_amd64.deb", Component: "agent", OS: "linux", Arch: "amd64", Format: "deb"},
			{Name: "surveyscan-agent_1.2.3_windows_x64.msi", Component: "agent", OS: "windows", Arch: "x64", Format: "msi"}})
	c, e := Load(dir, pub)
	if e != nil || !c.SignatureVerified || c.Version != "1.2.3" || len(c.Files) != 2 || c.Files[0].OS != "windows" {
		t.Fatalf("load: %v %+v", e, c)
	}
	b, f, e := c.Read("surveyscan-agent_1.2.3_windows_x64.msi")
	if e != nil || string(b) != string(msi) || f.SHA256 != sum(msi) || f.Bytes != int64(len(msi)) {
		t.Fatalf("read: %v %+v", e, f)
	}
	// файл подменён на диске после проверки выпуска — не отдаётся
	os.WriteFile(filepath.Join(dir, "installers", "surveyscan-agent_1.2.3-1_amd64.deb"), []byte("evil bytes"), 0o644)
	if _, _, e = c.Read("surveyscan-agent_1.2.3-1_amd64.deb"); !errors.Is(e, ErrMismatch) {
		t.Fatalf("tampered file served: %v", e)
	}
	for _, n := range []string{"../release-manifest.json", "index.json", "nope.msi", ""} {
		if _, _, e = c.Read(n); !errors.Is(e, ErrNotFound) {
			t.Fatalf("%q: %v", n, e)
		}
	}
	// без ключа — читается, но подпись не проверена центром
	if c, e = Load(dir, nil); e != nil || c.SignatureVerified {
		t.Fatalf("no key: %v %+v", e, c)
	}
}

func TestCatalogRejectsForeignSignatureAndUnlistedFiles(t *testing.T) {
	dir, _, _ := release(t, map[string][]byte{"a.msi": []byte("x")}, []File{{Name: "a.msi", Component: "agent", OS: "windows", Format: "msi"}})
	_, _, other := release(t, map[string][]byte{}, nil)
	if _, e := Load(dir, other); e == nil {
		t.Fatal("manifest signed by another key accepted")
	}
	dir2, _, pub2 := release(t, map[string][]byte{"a.msi": []byte("x")}, []File{{Name: "b.msi", Component: "agent", OS: "windows", Format: "msi"}})
	if _, e := Load(dir2, pub2); e == nil {
		t.Fatal("index entry outside the signed manifest accepted")
	}
	// выпуск без файлов установки — пустой каталог, не ошибка
	empty := t.TempDir()
	raw, _ := json.Marshal(map[string]any{"format": "surveyscan-release-v1", "version": "1.0.0", "files": map[string]any{}})
	os.WriteFile(filepath.Join(empty, "release-manifest.json"), raw, 0o644)
	if c, e := Load(empty, nil); e != nil || len(c.Files) != 0 {
		t.Fatalf("empty release: %v", e)
	}
}
