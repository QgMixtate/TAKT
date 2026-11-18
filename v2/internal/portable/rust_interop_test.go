package portable

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

// C52.03: пакет Rust-portable (agent-rs, бинарник surveyscan-portable) с шифрованием ключом центра открывается
// Go-центром (HPKE Open) и импортируется (подпись манифеста, наблюдение 1.2). Бинарник — SURVEYSCAN_RUST_PORTABLE.
func TestRustPortableEncryptedPackageImports(t *testing.T) {
	bin := os.Getenv("SURVEYSCAN_RUST_PORTABLE")
	if bin == "" {
		t.Skip("SURVEYSCAN_RUST_PORTABLE not set")
	}
	priv, pub, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	state, pkg := filepath.Join(dir, "state"), filepath.Join(dir, "audit.zip")
	out, err := exec.Command(bin, "init", "--state", state, "--tenant", "00000000-0000-4000-8000-000000000051", "--site", "00000000-0000-4000-8000-000000000052",
		"--scope", "00000000-0000-4000-8000-000000000053", "--center-key", base64.StdEncoding.EncodeToString(pub)).CombinedOutput()
	if err != nil {
		t.Fatal(string(out))
	}
	m := regexp.MustCompile(`public_key=(\S+)`).FindSubmatch(out)
	if m == nil {
		t.Fatal("no public key", string(out))
	}
	signing, err := base64.RawURLEncoding.DecodeString(string(m[1]))
	if err != nil || len(signing) != ed25519.PublicKeySize {
		t.Fatal("public key", err)
	}
	if out, err = exec.Command(bin, "collect", "--state", state, "--out", pkg).CombinedOutput(); err != nil {
		t.Fatal(string(out))
	}
	data, err := os.ReadFile(pkg)
	if err != nil || !Encrypted(data) {
		t.Fatal("package must be encrypted", err)
	}
	if id, _ := EnvelopeKeyID(data); id != EncryptionKeyID(pub) {
		t.Fatal("envelope addressed to another key", id)
	}
	plain, err := Open(priv, data)
	if err != nil {
		t.Fatal("open", err)
	}
	v, err := wire.NewInventory12()
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.PublicKey(signing)
	res, err := Import(plain, map[string]ed25519.PublicKey{KeyID(key): key}, Known{}, DefaultLimits(), v)
	if err != nil || len(res.Accepted) != 1 || len(res.Quarantined) != 0 {
		t.Fatal("import", err, res.Quarantined)
	}
	if out, err = exec.Command(bin, "collect", "--state", state, "--out", pkg).CombinedOutput(); err == nil {
		t.Fatal("an existing package must never be overwritten", string(out))
	}
}
