//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/installers"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/health"
)

// C52.04 (AC C52-07): файлы установки из подписанного выпуска — список и скачивание для администратора и оператора,
// наблюдателю — отказ; байты совпадают с подписанным manifest (SHA-256), скачивание в аудите; файл, подменённый на
// диске, не отдаётся.
func TestC52InstallersDownload(t *testing.T) {
	f := registrySetup(t)
	dir := t.TempDir()
	msi := []byte("MSI-agent-bytes")
	os.MkdirAll(filepath.Join(dir, "installers"), 0o755)
	idx, _ := json.Marshal(map[string]any{"format": "surveyscan-installers-v1", "files": []map[string]string{
		{"name": "surveyscan-agent_1.2.3_windows_x64.msi", "component": "agent", "os": "windows", "arch": "x64", "format": "msi"}}})
	files := map[string][]byte{"surveyscan-agent_1.2.3_windows_x64.msi": msi, "index.json": idx}
	entries := map[string]any{}
	for n, b := range files {
		os.WriteFile(filepath.Join(dir, "installers", n), b, 0o644)
		s := sha256.Sum256(b)
		entries["installers/"+n] = map[string]any{"sha256": hex.EncodeToString(s[:]), "bytes": len(b), "mode": 420}
	}
	raw, _ := json.Marshal(map[string]any{"format": "surveyscan-release-v1", "version": "1.2.3", "files": entries})
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	os.WriteFile(filepath.Join(dir, "release-manifest.json"), raw, 0o644)
	os.WriteFile(filepath.Join(dir, "release-manifest.sig"), ed25519.Sign(priv, raw), 0o644)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	catalog, err := installers.Load(dir, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	f.registry.Installers = catalog
	for _, u := range [][2]string{{"adm", "admin"}, {"op", "operator"}, {"view", "viewer"}} {
		if err := f.users.Provision(f.ctx, false, tenant, "", u[0], password, u[1]); err != nil {
			t.Fatal(err)
		}
	}
	auth, err := access.NewHTTP(f.users, "https://ui.example", false)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := app.NewHTTP(auth, health.Handler(func(context.Context) error { return nil }), f.registry)
	if err != nil {
		t.Fatal(err)
	}
	web := httptest.NewTLSServer(handler)
	defer web.Close()
	get := func(user, path string, want int) ([]byte, map[string][]string) {
		t.Helper()
		b := newBrowser(t, web)
		csrf := b.login(t, user).CSRFToken
		code, body, headers := b.request(t, "GET", path, "", csrf, "https://ui.example", nil)
		if code != want {
			t.Fatalf("%s GET %s: %d (want %d) %s", user, path, code, want, body)
		}
		return body, headers
	}
	list, _ := get("op", "/api/v1/installers", 200)
	validC52(t, "InstallerList", list)
	var probe map[string]any
	json.Unmarshal(list, &probe)
	if probe["available"] != true || probe["signature_verified"] != true || len(probe["files"].([]any)) != 1 {
		t.Fatalf("list: %s", list)
	}
	get("view", "/api/v1/installers", 403)
	get("view", "/api/v1/installers/surveyscan-agent_1.2.3_windows_x64.msi", 403)
	body, headers := get("adm", "/api/v1/installers/surveyscan-agent_1.2.3_windows_x64.msi", 200)
	sum := sha256.Sum256(body)
	if string(body) != string(msi) || headers["X-Installer-Sha256"] == nil || headers["X-Installer-Sha256"][0] != hex.EncodeToString(sum[:]) {
		t.Fatalf("download: %q %v", body, headers)
	}
	var audited int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND action='installer.downloaded' AND object_type='installer' AND object_id='surveyscan-agent_1.2.3_windows_x64.msi'`, tenant).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("audit: %d %v", audited, err)
	}
	get("op", "/api/v1/installers/nope.msi", 404)
	get("op", "/api/v1/installers/..%2Frelease-manifest.json", 404)
	// подмена файла на диске после старта центра — отказ, аудита скачивания нет
	os.WriteFile(filepath.Join(dir, "installers", "surveyscan-agent_1.2.3_windows_x64.msi"), []byte("evil-agent-bytes"), 0o644)
	get("op", "/api/v1/installers/surveyscan-agent_1.2.3_windows_x64.msi", 409)
	f.pool.QueryRow(f.ctx, `SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND action='installer.downloaded'`, tenant).Scan(&audited)
	if audited != 1 {
		t.Fatalf("tampered download audited: %d", audited)
	}
	// выпуск без файлов установки (разработка) — список пустой с причиной
	f.registry.Installers = nil
	list, _ = get("op", "/api/v1/installers", 200)
	validC52(t, "InstallerList", list)
	json.Unmarshal(list, &probe)
	if probe["available"] != false || probe["reason"] != "RELEASE_NOT_INSTALLED" {
		t.Fatalf("no release: %s", list)
	}
}
