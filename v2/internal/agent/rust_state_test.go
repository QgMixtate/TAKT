package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
)

// C52.02: состояние, созданное Rust-агентом (agent-rs/testdata/state, фиксированные затравки ключей 3 и 5),
// совпадает с форматом Go-агента: CSR проходит проверку центра, PEM ключей побайтно как у Go, привязка к машине
// та же. Значит, Rust-агент заменяет Go-агента на той же машине без перерегистрации.
func TestRustAgentStateIsCompatible(t *testing.T) {
	dir := "../../agent-rs/testdata/state"
	strict := func(name string, out any) {
		raw, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if e = d.Decode(out); e != nil {
			t.Fatal(name, e)
		}
	}
	var prep Preparation
	strict("preparation.json", &prep)
	_, hash, e := pki.ParseCSR(prep.CSR)
	if e != nil || hash != prep.Hash {
		t.Fatalf("CSR from Rust: %v %s %s", e, hash, prep.Hash)
	}
	keyPEM := func(seed byte) (ed25519.PrivateKey, string) {
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
		der, _ := x509.MarshalPKCS8PrivateKey(key)
		sum := sha256.Sum256(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
		return key, hex.EncodeToString(sum[:])
	}
	signing, signingSum := keyPEM(5)
	_, tlsSum := keyPEM(3)
	sums, _ := os.ReadFile(filepath.Join(dir, "keys.sha256"))
	if strings.Fields(string(sums))[0] != signingSum || strings.Fields(string(sums))[1] != tlsSum {
		t.Fatal("Rust PKCS#8 PEM differs from Go")
	}
	if prep.Public != base64.RawURLEncoding.EncodeToString(signing.Public().(ed25519.PublicKey)) {
		t.Fatal("signing public key mismatch")
	}
	var b hostBinding
	strict("host-binding.json", &b)
	if e = verifyBindingValue(b, prep.Source, "0123456789abcdef0123456789abcdef", signing); e != nil {
		t.Fatal(e)
	}
}
