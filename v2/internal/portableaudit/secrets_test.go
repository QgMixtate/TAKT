package portableaudit

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/internal/agent"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"github.com/QgMixtate/surveyscan/v2/internal/portable"
)

// C23.04: в пакет не попадают ключ подписи (в любом виде), содержимое каталога состояния, кроме открытых
// полей, и текст ошибок целей (там может оказаться пароль или путь к ключу). Проверяется РАСПАКОВАННОЕ
// содержимое каждой записи zip, а не сжатые байты.
func TestPackageCarriesNoSecrets(t *testing.T) {
	dir, _ := setup(t)
	const marker = "Pa55-portable-secret-marker"
	failing := Target{Kind: "winrm", Name: "pc.example.test", Collect: func(context.Context) (agent.Snapshot, error) {
		return agent.Snapshot{}, errors.New("winrm: login AWM\\scan password " + marker + " refused")
	}}
	out := filepath.Join(t.TempDir(), "audit.ssp")
	var lines []string
	if _, err := Run(context.Background(), dir, []Target{hostTarget(t), failing}, out, func(s string) { lines = append(lines, s) }); err != nil {
		t.Fatal(err)
	}
	keyB64, _ := os.ReadFile(filepath.Join(dir, "signing.key"))
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyB64)))
	if err != nil || len(seed) != 32 {
		t.Fatal("seed", err)
	}
	forbidden := map[string][]byte{"seed base64": bytes.TrimSpace(keyB64), "seed raw": seed, "seed base64url": []byte(base64.RawURLEncoding.EncodeToString(seed)), "target error": []byte(marker), "state dir": []byte(dir)}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if strings.Contains(f.Name, "key") && f.Name != "manifest.json" && !strings.HasPrefix(f.Name, "observations/") {
			t.Fatalf("unexpected key-like entry %q", f.Name)
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		for what, b := range forbidden {
			if bytes.Contains(body, b) {
				t.Fatalf("package entry %q contains %s", f.Name, what)
			}
		}
	}
	for what, b := range forbidden {
		if what != "target error" && what != "state dir" && bytes.Contains(data, b) {
			t.Fatalf("raw package contains %s", what)
		}
	}
	// ошибку цели оператор видит в выводе (для разбора), но в пакет она не уходит
	if !strings.Contains(strings.Join(lines, "\n"), "pc.example.test") {
		t.Fatal("failed target must be reported to the operator:", lines)
	}
}

// Шифрование для центра: пакет нечитаем без ключа центра, после расшифровки — тот же проверяемый пакет;
// второй, другой ключ центра для того же каталога не принимается (пакеты не уходят незаметно к чужому ключу).
func TestEncryptedPackageForCentre(t *testing.T) {
	dir, pub := setup(t)
	priv, centre, err := portable.GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(centre)
	if _, err = SetCenterKey(dir, b64); err != nil {
		t.Fatal(err)
	}
	if _, err = SetCenterKey(dir, b64); err != nil {
		t.Fatal("same key again must be accepted:", err)
	}
	_, other, _ := portable.GenerateEncryptionKey()
	if _, err = SetCenterKey(dir, base64.StdEncoding.EncodeToString(other)); err == nil {
		t.Fatal("another centre key must be refused")
	}
	if _, err = SetCenterKey(dir, "not-a-key"); err == nil {
		t.Fatal("garbage key must be refused")
	}
	out := filepath.Join(t.TempDir(), "audit.zip")
	rep, err := Run(context.Background(), dir, []Target{hostTarget(t)}, out, nil)
	if err != nil || !rep.Encrypted {
		t.Fatal("encrypted export:", err, rep.Encrypted)
	}
	data, _ := os.ReadFile(out)
	if !portable.Encrypted(data) || bytes.Contains(data, []byte("manifest.json")) {
		t.Fatal("package must be an opaque envelope")
	}
	plain, err := portable.Open(priv, data)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := wire.NewInventory12()
	res, err := portable.Import(plain, map[string]ed25519.PublicKey{portable.KeyID(pub): pub}, portable.Known{}, portable.DefaultLimits(), v)
	if err != nil || len(res.Accepted) != 1 {
		t.Fatal("decrypted package must import:", err)
	}
}
