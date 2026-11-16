//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/collector"
	"github.com/QgMixtate/surveyscan/v2/internal/enrollpin"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/health"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// C52.01 (AC C52-06): установка по коду — код показывается один раз (в центре только хеш), отпечаток центра
// обязателен, collector регистрируется целиком (ключи на машине, enroll, конфигурация 0600), агентский код на N
// установок: N проходят, N+1-я и отозванный/просроченный — отказ, повтор того же CSR не создаёт второй источник.
func validC52(t *testing.T, def string, raw []byte) {
	t.Helper()
	schemaRaw, err := os.ReadFile("../../contracts/c52-registration.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	doc, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(schemaRaw)))
	if err = compiler.AddResource("urn:surveyscan:c52:registration:1:0", doc); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("urn:surveyscan:c52:registration:1:0#/$defs/" + def)
	if err != nil {
		t.Fatal(err)
	}
	inst, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
	if err = schema.Validate(inst); err != nil {
		t.Fatalf("%s violates c52-registration: %v %s", def, err, raw)
	}
}

func TestC52RegistrationCodes(t *testing.T) {
	f := registrySetup(t)
	s, authority := machineService(t, f)
	f.registry.Machine = &app.MachineAPI{Sources: s, CA: authority.Certificate, Fingerprint: app.CenterFingerprint(authority.Certificate)}
	for _, u := range [][2]string{{"adm", "admin"}, {"op", "operator"}} {
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
	// машинный адрес центра: сертификат от УЦ центра (как в эксплуатации)
	_, leafKey, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "center"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, authority.Certificate, leafKey.Public(), authority.Key)
	if err != nil {
		t.Fatal(err)
	}
	center := httptest.NewUnstartedServer(handler)
	center.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: leafKey}}}
	center.StartTLS()
	defer center.Close()
	fp := app.CenterFingerprint(authority.Certificate)

	login := func(user string) (browser, string) { b := newBrowser(t, web); return b, b.login(t, user).CSRFToken }
	adm, admCSRF := login("adm")
	op, opCSRF := login("op")
	call := func(b browser, csrf, method, path, body string, want int) []byte {
		t.Helper()
		code, raw, _ := b.request(t, method, path, body, csrf, "https://ui.example", nil)
		if code != want {
			t.Fatalf("%s %s: %d (want %d) %s", method, path, code, want, raw)
		}
		return raw
	}
	newCode := func(body string) sources.RegistrationCode {
		t.Helper()
		var c sources.RegistrationCode
		raw := call(adm, admCSRF, "POST", "/api/v1/registration-codes", body, 201)
		validC52(t, "RegistrationCode", raw)
		_ = json.Unmarshal(raw, &c)
		if sources.NormalizeCode(c.Code) != c.Code || c.Fingerprint != fp || c.State != "active" {
			t.Fatalf("code: %+v", c)
		}
		return c
	}
	call(op, opCSRF, "POST", "/api/v1/registration-codes", fmt.Sprintf(`{"source_kind":"collector","site_id":%q,"max_uses":1,"ttl_hours":1}`, siteID), 403)
	call(adm, admCSRF, "POST", "/api/v1/registration-codes", fmt.Sprintf(`{"source_kind":"collector","site_id":%q,"max_uses":0,"ttl_hours":1}`, siteID), 422)
	call(adm, admCSRF, "POST", "/api/v1/registration-codes", fmt.Sprintf(`{"source_kind":"agent","site_id":%q,"max_uses":1,"ttl_hours":1}`, siteID), 422) // агенту нужен collector
	cc := newCode(fmt.Sprintf(`{"source_kind":"collector","site_id":%q,"max_uses":1,"ttl_hours":24,"comment":"Площадка 1"}`, siteID))
	var stored int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM sources.registration_codes WHERE code_hash=$1 OR comment=$1", cc.Code).Scan(&stored)
	if stored != 0 {
		t.Fatal("plain code must not be stored")
	}

	// collector: неверный отпечаток — отказ до регистрации; верный — ключи, enroll, конфигурация
	ctx, cancel := context.WithTimeout(f.ctx, time.Minute)
	defer cancel()
	dir := t.TempDir()
	opts := collector.RegisterOptions{CenterURL: center.URL, Code: strings.ToLower(cc.Code), Fingerprint: strings.Repeat("ab", 32), Dir: filepath.Join(dir, "etc"), StateDir: filepath.Join(dir, "var"), Listen: "127.0.0.1:0", Hostname: "collector-1"}
	if _, err = collector.Register(ctx, opts); err == nil || !strings.Contains(err.Error(), "отпечаток") {
		t.Fatal("wrong fingerprint must stop registration", err)
	}
	opts.Fingerprint = fp
	collectorSource, err := collector.Register(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"collector.json", "collector.key", "origin-signing.key", "collector.pem", "ca.pem"} {
		st, err := os.Stat(filepath.Join(opts.Dir, name))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", name, err, st)
		}
	}
	if _, err = collector.Load(filepath.Join(opts.Dir, "collector.json")); err != nil {
		t.Fatal("written collector config must load", err)
	}
	var state string
	_ = f.pool.QueryRow(f.ctx, "SELECT state FROM sources.sources WHERE source_id=$1", collectorSource).Scan(&state)
	if state != "active" {
		t.Fatal("collector source must be active after enroll", state)
	}
	opts2 := opts
	opts2.Dir, opts2.StateDir = filepath.Join(dir, "etc2"), filepath.Join(dir, "var2")
	if _, err = collector.Register(ctx, opts2); err == nil || !strings.Contains(err.Error(), "код не принят") {
		t.Fatal("single-use code must be exhausted", err)
	}

	// агентский код на 2 установки, привязан к collector площадки
	ac := newCode(fmt.Sprintf(`{"source_kind":"agent","site_id":%q,"collector_source_id":%q,"inventory_platform":"windows/amd64","max_uses":2,"ttl_hours":24}`, siteID, collectorSource))
	register := func(csrHash, pub, host, platform string) (sources.RegistrationResult, error) {
		var out sources.RegistrationResult
		err := enrollpin.PostRegistration(ctx, center.URL, authority.Certificate, "", map[string]string{"registration_code": ac.Code, "source_id": identifier.New(), "csr_sha256": csrHash,
			"signing_public_key": pub, "hostname": host, "inventory_platform": platform}, &out)
		return out, err
	}
	csr1, hash1, pub1 := csrMaterial(t)
	if _, err = register(hash1, pub1, "pc-1", "linux/amd64"); err == nil {
		t.Fatal("platform outside the code must be rejected")
	}
	r1, err := register(hash1, pub1, "pc-1", "windows/amd64")
	if err != nil || r1.CollectorSource == nil || *r1.CollectorSource != collectorSource || r1.Tenant != tenant || r1.Scope == "" {
		t.Fatalf("agent registration: %+v %v", r1, err)
	}
	if _, err = register(hash1, pub1, "pc-1", "windows/amd64"); err == nil || !strings.Contains(err.Error(), "уже зарегистрирована") {
		t.Fatal("same CSR must not create a second source", err)
	}
	if _, err = s.Enroll(f.ctx, r1.Grant.Token, contracts.EnrollmentRequest{GrantID: r1.Grant.ID, SourceID: r1.Grant.SourceID, CSR: csr1, PublicKey: pub1}); err != nil {
		t.Fatal("registered agent enrolls as usual", err)
	}
	_, hash2, pub2 := csrMaterial(t)
	if _, err = register(hash2, pub2, "pc-2", "windows/amd64"); err != nil {
		t.Fatal(err)
	}
	_, hash3, pub3 := csrMaterial(t)
	if _, err = register(hash3, pub3, "pc-3", "windows/amd64"); err == nil || !strings.Contains(err.Error(), "код не принят") {
		t.Fatal("N+1 install must be rejected", err)
	}
	raw := call(adm, admCSRF, "GET", "/api/v1/registration-codes/"+ac.ID+"/uses", "", 200)
	validC52(t, "RegistrationUseList", raw)
	rawResult, _ := json.Marshal(r1)
	validC52(t, "RegistrationResult", rawResult)
	if !strings.Contains(string(raw), "pc-1") || !strings.Contains(string(raw), "pc-2") {
		t.Fatalf("uses: %s", raw)
	}
	// отзыв и срок
	rc := newCode(fmt.Sprintf(`{"source_kind":"agent","site_id":%q,"collector_source_id":%q,"max_uses":5,"ttl_hours":24}`, siteID, collectorSource))
	call(adm, admCSRF, "POST", "/api/v1/registration-codes/"+rc.ID+"/revoke", "{}", 200)
	ac = rc
	if _, err = register(hash3, pub3, "pc-3", "windows/amd64"); err == nil {
		t.Fatal("revoked code must be rejected")
	}
	ec := newCode(fmt.Sprintf(`{"source_kind":"agent","site_id":%q,"collector_source_id":%q,"max_uses":5,"ttl_hours":24}`, siteID, collectorSource))
	_, _ = f.pool.Exec(f.ctx, "UPDATE sources.registration_codes SET expires_at=now()-interval '1 minute' WHERE code_id=$1", ec.ID)
	ac = ec
	if _, err = register(hash3, pub3, "pc-3", "windows/amd64"); err == nil {
		t.Fatal("expired code must be rejected")
	}
	raw = call(adm, admCSRF, "GET", "/api/v1/registration-codes", "", 200)
	validC52(t, "RegistrationCodeList", raw)
	for _, want := range []string{`"state":"exhausted"`, `"state":"revoked"`, `"state":"expired"`, fp} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("list must show %s: %s", want, raw)
		}
	}
	if strings.Contains(string(raw), `"code":"SSR`) {
		t.Fatal("list must not reveal codes")
	}
	var audits int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND action LIKE 'source.registration_code_%'", tenant).Scan(&audits)
	if audits != 5 {
		t.Fatal("code actions must be audited", audits)
	}
}
