//go:build integration

package app_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/health"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// C51.01: обследования сети — правила D-13 на сервере (/22, пробы, расписание ≥ 60 мин, collector той же площадки),
// права (админ заводит, оператор запускает, наблюдатель только смотрит), одно незавершённое обследование на подсеть,
// задание только collector своей подсети (mTLS), подписанный результат, scope не расширяется, present/missing, аудит.
func TestC51DiscoveryPolicyRightsJobAndSignedResult(t *testing.T) {
	f := registrySetup(t)
	machine, authority := machineService(t, f)
	f.registry.Machine = &app.MachineAPI{Sources: machine}
	for _, u := range []struct{ name, role string }{{"op51", "operator"}, {"view51", "viewer"}} {
		if err := f.users.Provision(f.ctx, false, tenant, "", u.name, password, u.role); err != nil {
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
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	contract, err := os.ReadFile("../../contracts/c51-discovery.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(contract)))
	if err = compiler.AddResource("urn:surveyscan:c51:discovery:1:0", doc); err != nil {
		t.Fatal(err)
	}
	valid := func(def string, raw []byte) {
		t.Helper()
		schema, err := compiler.Compile("urn:surveyscan:c51:discovery:1:0#/$defs/" + def)
		if err != nil {
			t.Fatal(err)
		}
		instance, err := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
		if err != nil || schema.Validate(instance) != nil {
			t.Fatalf("%s violates contract: %v %s", def, schema.Validate(instance), raw)
		}
	}
	human := httptest.NewTLSServer(handler)
	t.Cleanup(human.Close)
	sessions51 := map[string]c31Client{}
	call := func(user, method, path, body string, want int) []byte {
		t.Helper()
		b, ok := sessions51[user]
		if !ok {
			b.b = newBrowser(t, human)
			b.csrf = b.b.login(t, user).CSRFToken
			sessions51[user] = b
		}
		csrf, origin := b.csrf, "https://ui.example"
		if method == "GET" {
			csrf, origin = "", ""
		}
		code, raw, _ := b.b.request(t, method, path, body, csrf, origin, nil)
		if code != want {
			t.Fatalf("%s %s %s: want %d, got %d %s", user, method, path, want, code, raw)
		}
		return raw
	}
	// collector площадки (mTLS) с собственным ключом подписи
	signPub, signKey, _ := ed25519.GenerateKey(rand.Reader)
	csr, hash, _, tlsKey := csrTLSMaterial(t)
	collector := identifier.New()
	grant, err := machine.Grant(f.ctx, f.identity, contracts.EnrollmentGrantRequest{TenantID: tenant, SourceID: collector, Kind: "collector", SiteID: siteID, TTL: 900, CSRHash: hash, PublicKey: base64.RawURLEncoding.EncodeToString(signPub)})
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := machine.Enroll(f.ctx, grant.Token, contracts.EnrollmentRequest{GrantID: grant.ID, SourceID: collector, CSR: csr, PublicKey: base64.RawURLEncoding.EncodeToString(signPub)})
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, serverKey, _ := ed25519.GenerateKey(rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(51), Subject: pkix.Name{CommonName: "C51 fixture"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, authority.Certificate, serverPublic, authority.Key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority.Certificate)
	ms := httptest.NewUnstartedServer(handler)
	ms.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{tlsPair(t, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), serverKey)}, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: roots}
	ms.StartTLS()
	t.Cleanup(ms.Close)
	pair := tlsPair(t, enrolled.Chain, tlsKey)
	mc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{pair}}}}
	post := func(path string, body []byte) (int, []byte) {
		t.Helper()
		res, err := mc.Post(ms.URL+path, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		return res.StatusCode, raw
	}

	// правила D-13
	net51 := func(cidr string, extra string) string {
		return fmt.Sprintf(`{"site_id":%q,"collector_id":%q,"name":"Офис %s","cidr":%q,"probes":["tcp","arp","icmp"]%s}`, siteID, collector, cidr, cidr, extra)
	}
	for _, bad := range []string{net51("10.0.0.0/21", ""), net51("10.0.0.1/24", ""), net51("fd00::/120", ""), net51("10.0.0.0/24", `,"schedule_minutes":30`),
		strings.Replace(net51("10.0.0.0/24", ""), `"tcp","arp","icmp"`, `"udp"`, 1), strings.Replace(net51("10.0.0.0/24", ""), collector, identifier.New(), 1)} {
		call("admin", "POST", "/api/v1/discovery/networks", bad, 422)
	}
	call("op51", "POST", "/api/v1/discovery/networks", net51("10.0.0.0/24", ""), 403)
	var n sources.DiscoveryNetwork
	created := call("admin", "POST", "/api/v1/discovery/networks", net51("10.51.0.0/24", `,"schedule_minutes":60`), 201)
	valid("DiscoveryNetwork", created)
	_ = json.Unmarshal(created, &n)
	if n.ID == "" || n.CIDR != "10.51.0.0/24" || n.Revision != "1" {
		t.Fatalf("network %+v", n)
	}
	call("admin", "POST", "/api/v1/discovery/networks", net51("10.51.0.0/24", ""), 409) // та же подсеть
	call("view51", "POST", "/api/v1/discovery/networks/"+n.ID+"/runs", "{}", 403)
	var run struct {
		Run string `json:"run_id"`
	}
	_ = json.Unmarshal(call("op51", "POST", "/api/v1/discovery/networks/"+n.ID+"/runs", "{}", 202), &run)
	call("op51", "POST", "/api/v1/discovery/networks/"+n.ID+"/runs", "{}", 409) // одно незавершённое
	page := call("view51", "GET", "/api/v1/discovery/networks", "", 200)
	valid("DiscoveryNetworkPage", page)
	valid("DiscoveryRunPage", call("view51", "GET", "/api/v1/discovery/networks/"+n.ID+"/runs", "", 200))
	if !strings.Contains(string(page), `"max_prefix":22`) {
		t.Fatal("limits must be visible to the Web")
	}

	// задание — только collector подсети, по mTLS
	anon := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}}
	if res, err := anon.Post(ms.URL+"/api/v1/machine/discovery-jobs", "application/json", strings.NewReader("{}")); err != nil || res.StatusCode != 401 {
		t.Fatal("job without client certificate", err)
	}
	code, raw := post("/api/v1/machine/discovery-jobs", []byte("{}"))
	var got struct {
		Job *sources.DiscoveryJob `json:"job"`
	}
	valid("DiscoveryJobResponse", raw)
	if code != 200 || json.Unmarshal(raw, &got) != nil || got.Job == nil || got.Job.Run != run.Run || got.Job.CIDR != "10.51.0.0/24" || got.Job.Rate != 50 || len(got.Job.Probes) != 3 {
		t.Fatalf("job %d %s", code, raw)
	}
	if code, raw = post("/api/v1/machine/discovery-jobs", []byte("{}")); code != 200 || string(raw) != `{"job":null}`+"\n" && string(raw) != `{"job":null}` {
		t.Fatalf("second claim must be empty: %d %s", code, raw)
	}

	submit := func(hosts []sources.FoundHost, errs []string, key ed25519.PrivateKey) (int, []byte) {
		payload, _ := json.Marshal(sources.DiscoveryResult{Major: 1, ResultID: identifier.New(), Tenant: tenant, Source: collector, Generation: enrolled.GenerationID, Run: run.Run,
			StartedAt: time.Now().Add(-time.Minute).UTC(), FinishedAt: time.Now().UTC(), Addresses: 254, Hosts: hosts, Errors: errs})
		canonical, _ := wire.Canonical(payload)
		sum := sha256.Sum256(canonical)
		sig := ed25519.Sign(key, append([]byte(sources.DiscoverySignaturePrefix), canonical...))
		body, _ := json.Marshal(sources.SignedDiscoveryResult{Payload: payload, Digest: hex.EncodeToString(sum[:]), KeyID: enrolled.KeyID, Signature: base64.RawURLEncoding.EncodeToString(sig)})
		valid("SignedDiscoveryResult", body)
		return post("/api/v1/machine/discovery-results", body)
	}
	mac := "AA:BB:CC:00:00:01"
	hosts := []sources.FoundHost{{IP: "10.51.0.10", MAC: &mac, Ports: []int{22, 9999, 22}, ICMP: true, PTR: "linux01.lab51.local"}, {IP: "10.51.0.20", Ports: []int{445, 3389}}, {IP: "192.168.1.1", Ports: []int{80}}}
	_, foreign, _ := ed25519.GenerateKey(rand.Reader)
	if code, _ := submit(hosts, nil, foreign); code < 400 {
		t.Fatal("result signed by another key accepted")
	}
	code, raw = submit(hosts, nil, signKey)
	var out sources.DiscoveryOutcome
	valid("DiscoveryOutcome", raw)
	if code != 200 || json.Unmarshal(raw, &out) != nil || out.Found != 2 || out.New != 2 || out.Dropped != 1 {
		t.Fatalf("result %d %s", code, raw)
	}
	var hl struct {
		Items []sources.DiscoveryHost `json:"items"`
	}
	hostsRaw := call("view51", "GET", "/api/v1/discovery/networks/"+n.ID+"/hosts", "", 200)
	valid("DiscoveryHostPage", hostsRaw)
	_ = json.Unmarshal(hostsRaw, &hl)
	if len(hl.Items) != 2 || hl.Items[0].IP != "10.51.0.10" || *hl.Items[0].MAC != "aa:bb:cc:00:00:01" || len(hl.Items[0].Ports) != 1 || !hl.Items[0].ICMP ||
		hl.Items[0].PTR == nil || *hl.Items[0].PTR != "linux01.lab51.local" || hl.Items[1].PTR != nil {
		t.Fatalf("hosts %+v", hl.Items)
	}
	// второе обследование: .20 пропал, .30 новый
	_ = json.Unmarshal(call("op51", "POST", "/api/v1/discovery/networks/"+n.ID+"/runs", "{}", 202), &run)
	if code, _ = post("/api/v1/machine/discovery-jobs", []byte("{}")); code != 200 {
		t.Fatal(code)
	}
	code, raw = submit([]sources.FoundHost{{IP: "10.51.0.10", Ports: []int{22}}, {IP: "10.51.0.30", Ports: []int{443}}}, nil, signKey)
	// C21: один пропуск — ещё не «пропал» (порог — 3 полных обследования подряд)
	if code != 200 || json.Unmarshal(raw, &out) != nil || out.Found != 2 || out.New != 1 || out.Missing != 0 {
		t.Fatalf("second result %d %s", code, raw)
	}
	// повтор того же результата — без изменений
	if code, raw = submit(nil, nil, signKey); code != 200 || json.Unmarshal(raw, &out) != nil || out.Missing != 0 || out.New != 1 {
		t.Fatalf("replay of a finished run %d %s", code, raw)
	}
	hostState := func(ip string) sources.DiscoveryHost {
		t.Helper()
		raw := call("view51", "GET", "/api/v1/discovery/networks/"+n.ID+"/hosts", "", 200)
		valid("DiscoveryHostPage", raw)
		var l struct {
			Items []sources.DiscoveryHost `json:"items"`
		}
		_ = json.Unmarshal(raw, &l)
		for _, h := range l.Items {
			if h.IP == ip {
				return h
			}
		}
		t.Fatal("host not listed", ip)
		return sources.DiscoveryHost{}
	}
	pass := func(found []sources.FoundHost, errs []string) sources.DiscoveryOutcome {
		t.Helper()
		_ = json.Unmarshal(call("op51", "POST", "/api/v1/discovery/networks/"+n.ID+"/runs", "{}", 202), &run)
		if code, _ := post("/api/v1/machine/discovery-jobs", []byte("{}")); code != 200 {
			t.Fatal(code)
		}
		code, raw := submit(found, errs, signKey)
		var o sources.DiscoveryOutcome
		if code != 200 || json.Unmarshal(raw, &o) != nil {
			t.Fatalf("pass %d %s", code, raw)
		}
		return o
	}
	// C57.03: обследование без ответа DNS имя не стирает
	if h := hostState("10.51.0.10"); h.PTR == nil || *h.PTR != "linux01.lab51.local" {
		t.Fatalf("PTR name must survive a run without DNS answer: %+v", h)
	}
	if h := hostState("10.51.0.20"); h.State != "present" || h.Misses != 1 || h.MissingSince != nil {
		t.Fatalf("one miss: %+v", h)
	}
	seen := []sources.FoundHost{{IP: "10.51.0.10", Ports: []int{22}}, {IP: "10.51.0.30", Ports: []int{443}}}
	// обследование с ошибками (часть адресов не опрошена) пропуск не засчитывает (AC-31)
	if o := pass(seen, []string{"icmp_unavailable"}); o.Missing != 0 || hostState("10.51.0.20").Misses != 1 {
		t.Fatalf("partial pass counted a miss: %+v %+v", o, hostState("10.51.0.20"))
	}
	if o := pass(seen, nil); o.Missing != 0 || hostState("10.51.0.20").Misses != 2 {
		t.Fatal("second complete miss", o)
	}
	if o := pass(seen, nil); o.Missing != 1 {
		t.Fatal("third complete miss must mark the host missing", o)
	}
	if h := hostState("10.51.0.20"); h.State != "missing" || h.MissingSince == nil || h.Misses != 3 {
		t.Fatalf("missing after the threshold: %+v", h)
	}
	if o := pass(append(seen, sources.FoundHost{IP: "10.51.0.20", Ports: []int{445}}), nil); o.New != 0 || o.Missing != 0 {
		t.Fatal("return is not a new host", o)
	}
	if h := hostState("10.51.0.20"); h.State != "present" || h.Misses != 0 || h.MissingSince != nil {
		t.Fatalf("returned host: %+v", h)
	}
	evRaw := call("view51", "GET", "/api/v1/discovery/networks/"+n.ID+"/events", "", 200)
	valid("DiscoveryHostEventList", evRaw)
	var ev struct {
		Items []sources.DiscoveryHostEvent `json:"items"`
	}
	_ = json.Unmarshal(evRaw, &ev)
	kinds := map[string]int{}
	for _, e := range ev.Items {
		if e.IP == "10.51.0.20" {
			kinds[e.Kind]++
		}
	}
	if len(ev.Items) != 5 || kinds["appeared"] != 1 || kinds["missing"] != 1 || kinds["returned"] != 1 || ev.Items[0].Kind != "returned" {
		t.Fatalf("presence events: %+v", ev.Items)
	}
	// C21.02: присутствие актива — по совпадению его адресов с узлами обследований (контракт c21-presence)
	presenceRaw, err := os.ReadFile("../../contracts/c21-presence.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	pdoc, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(presenceRaw)))
	if err = compiler.AddResource("urn:surveyscan:c21:presence:1:0", pdoc); err != nil {
		t.Fatal(err)
	}
	pschema, err := compiler.Compile("urn:surveyscan:c21:presence:1:0#/$defs/AssetPresence")
	if err != nil {
		t.Fatal(err)
	}
	presence := func(uid string) app.AssetPresence {
		t.Helper()
		raw := call("view51", "GET", "/api/v1/assets/"+uid+"/presence", "", 200)
		inst, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
		if e := pschema.Validate(inst); e != nil {
			t.Fatalf("AssetPresence violates contract: %v %s", e, raw)
		}
		var p app.AssetPresence
		_ = json.Unmarshal(raw, &p)
		return p
	}
	obs := f.observation("1")
	obs.Sections[2].Records = []map[string]any{{"name": "eth0", "mac": "aa:bb:cc:dd:ee:20", "addresses": []any{map[string]any{"ip": "10.51.0.20", "prefix": 24}}}}
	res := f.ingest(t, obs)
	if res.AssetID == nil {
		t.Fatalf("asset for presence: %+v", res)
	}
	if h := hostState("10.51.0.20"); h.Asset == nil || *h.Asset != *res.AssetID {
		t.Fatalf("discovery host must link to the registry asset with its address: %+v", h)
	}
	if h := hostState("10.51.0.30"); h.Asset != nil {
		t.Fatalf("host without inventory must show no asset: %+v", h)
	}
	if p := presence(*res.AssetID); p.State != "present" || len(p.Items) != 1 || p.Items[0].IP != "10.51.0.20" || p.Items[0].NetworkName == "" || p.MissAfter != 3 {
		t.Fatalf("asset presence: %+v", p)
	}
	for i := 0; i < 3; i++ {
		pass(seen, nil)
	}
	if p := presence(*res.AssetID); p.State != "missing" || p.Items[0].MissingSince == nil {
		t.Fatalf("asset presence after 3 misses: %+v", p)
	}
	// стенд №14: обследование, не взятое collector, снимается из очереди; взятое — уже нельзя
	var queued sources.DiscoveryOutcome
	_ = json.Unmarshal(call("op51", "POST", "/api/v1/discovery/networks/"+n.ID+"/runs", "{}", 202), &queued)
	call("view51", "POST", "/api/v1/discovery/networks/"+n.ID+"/runs/"+queued.Run+"/cancel", "{}", 403)
	call("op51", "POST", "/api/v1/discovery/networks/"+n.ID+"/runs/"+queued.Run+"/cancel", "{}", 200)
	call("op51", "POST", "/api/v1/discovery/networks/"+n.ID+"/runs/"+queued.Run+"/cancel", "{}", 409)
	if h := hostState("10.51.0.10"); h.Misses != 0 {
		t.Fatal("cancelled run must not count misses", h)
	}
	var audits int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND action LIKE 'discovery.%'", tenant).Scan(&audits); err != nil || audits != 12 {
		t.Fatal("audit of network creation and runs", audits, err)
	}
	// C51.03 шаг B: цель сбора из найденного узла — учётка, отпечаток ключа хоста, регистрация агента цели через grant
	f.registry.Secrets = app.FileSecrets{Dir: t.TempDir()}
	var cred sources.CollectCredential
	_ = json.Unmarshal(call("admin", "POST", "/api/v1/discovery/credentials", `{"name":"Linux RO","kind":"ssh","username":"scanprobe","secret":{"password":"c51-target-secret"}}`, 201), &cred)
	// ключ, созданный центром: закрытый — только в хранилище секретов, открытый — в ответе (строка authorized_keys)
	genRaw := call("admin", "POST", "/api/v1/discovery/credentials", `{"name":"Linux gen","kind":"ssh","username":"scanprobe","secret":{"generate":true}}`, 201)
	var gen sources.CollectCredential
	valid("CollectCredential", genRaw)
	_ = json.Unmarshal(genRaw, &gen)
	if gen.PublicKey == nil || !strings.HasPrefix(*gen.PublicKey, "ssh-ed25519 ") || strings.Contains(string(genRaw), "PRIVATE KEY") {
		t.Fatalf("generated credential: %s", genRaw)
	}
	stored, ok, err := f.registry.Secrets.Get(f.ctx, tenant, sources.CredentialSecretKey(gen.ID))
	if err != nil || !ok {
		t.Fatal("generated private key must be stored", err)
	}
	var sec struct {
		PrivateKey string `json:"private_key"`
	}
	_ = json.Unmarshal(stored, &sec)
	signer, err := ssh.ParsePrivateKey([]byte(sec.PrivateKey))
	if err != nil || !strings.HasPrefix(*gen.PublicKey, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))) {
		t.Fatal("stored private key must match the shown public key", err)
	}
	call("admin", "POST", "/api/v1/discovery/credentials", `{"name":"bad gen","kind":"ssh","username":"x","secret":{"generate":true,"password":"p"}}`, 422)
	call("admin", "POST", "/api/v1/discovery/credentials", `{"name":"bad gen2","kind":"winrm","username":"x","secret":{"generate":true}}`, 422)
	// смена секрета на пароль очищает открытый ключ
	var patched sources.CollectCredential
	_ = json.Unmarshal(call("admin", "PATCH", "/api/v1/discovery/credentials/"+gen.ID, `{"revision":"`+gen.Revision+`","secret":{"password":"new-secret"}}`, 200), &patched)
	if patched.PublicKey != nil {
		t.Fatal("public key must be cleared when the secret is replaced", *patched.PublicKey)
	}
	hostKey := "SHA256:" + strings.Repeat("A", 43)
	target51 := func(extra string) string {
		return fmt.Sprintf(`{"collector_id":%q,"network_id":%q,"address":"10.51.0.10","kind":"ssh","credential_id":%q%s}`, collector, n.ID, cred.ID, extra)
	}
	call("admin", "POST", "/api/v1/discovery/targets", strings.Replace(target51(`,"host_key_sha256":"`+hostKey+`"`), "10.51.0.10", "10.99.0.1", 1), 422) // вне подсети
	call("op51", "POST", "/api/v1/discovery/targets", target51(`,"host_key_sha256":"`+hostKey+`"`), 403)
	var tg sources.RemoteTarget
	_ = json.Unmarshal(call("admin", "POST", "/api/v1/discovery/targets", target51(`,"host_key_sha256":"`+hostKey+`"`), 201), &tg)
	if tg.State != "pending" || tg.Port != 22 || tg.Source != nil {
		t.Fatalf("target %+v", tg)
	}
	// Стенд №17: вторая неотключённая цель того же вида на тот же адрес — понятный код, а не «Состояние изменилось».
	if dup := call("admin", "POST", "/api/v1/discovery/targets", target51(`,"host_key_sha256":"`+hostKey+`"`), 409); !strings.Contains(string(dup), "TARGET_EXISTS") {
		t.Fatalf("duplicate target error %s", dup)
	}
	code, raw = post("/api/v1/machine/collect-targets", []byte("{}"))
	if code != 200 || !strings.Contains(string(raw), tg.ID) || !strings.Contains(string(raw), "scanprobe") || strings.Contains(string(raw), "c51-target-secret") {
		t.Fatalf("collector targets %d %s", code, raw)
	}
	// collector готовит личность агента цели и получает grant; регистрация — обычным путём агента
	agentCSR, agentHash, _, _ := csrTLSMaterial(t)
	agentPub, _, _ := ed25519.GenerateKey(rand.Reader)
	agentSource := identifier.New()
	grantBody, _ := json.Marshal(sources.TargetGrantRequest{Source: agentSource, CSRHash: agentHash, Public: base64.RawURLEncoding.EncodeToString(agentPub)})
	code, raw = post("/api/v1/machine/collect-targets/"+tg.ID+"/grant", grantBody)
	var tgrant contracts.EnrollmentGrant
	if code != 200 || json.Unmarshal(raw, &tgrant) != nil || tgrant.SourceID != agentSource {
		t.Fatalf("target grant %d %s", code, raw)
	}
	if code, _ = post("/api/v1/machine/collect-targets/"+tg.ID+"/grant", grantBody); code < 400 {
		t.Fatal("second grant for the same target accepted")
	}
	if _, err := machine.Enroll(f.ctx, tgrant.Token, contracts.EnrollmentRequest{GrantID: tgrant.ID, SourceID: agentSource, CSR: agentCSR, PublicKey: base64.RawURLEncoding.EncodeToString(agentPub)}); err != nil {
		t.Fatal("agent enrollment with the target grant", err)
	}
	if code, _ = post("/api/v1/machine/collect-targets/"+tg.ID+"/report", []byte(`{"ok":true,"problem":""}`)); code != 204 {
		t.Fatal("report", code)
	}
	var tl struct {
		Items []sources.RemoteTarget `json:"items"`
	}
	_ = json.Unmarshal(call("view51", "GET", "/api/v1/discovery/targets", "", 200), &tl)
	if len(tl.Items) != 1 || tl.Items[0].State != "active" || tl.Items[0].Source == nil || *tl.Items[0].Source != agentSource || tl.Items[0].LastCollected == nil {
		t.Fatalf("target after enrollment %+v", tl.Items)
	}
	// C53.07: «Что / сколько» — у collector одна SSH-цель, у источника цели — кто и по какому адресу его собирает
	var so struct {
		Items []app.SourceOverview `json:"items"`
	}
	_ = json.Unmarshal(call("view51", "GET", "/api/v1/sources/overview?ids="+collector+","+agentSource, "", 200), &so)
	byID := map[string]app.SourceOverview{}
	for _, o := range so.Items {
		byID[o.SourceID] = o
	}
	if c, a := byID[collector], byID[agentSource]; len(so.Items) != 2 || c.Targets.SSH != 1 || c.Targets.Errors != 0 || c.CollectedBy != nil ||
		a.CollectedBy == nil || a.CollectedBy.CollectorID != collector || a.CollectedBy.Kind != "ssh" || a.CollectedBy.Address != "10.51.0.10" || a.LastCollectedAt == nil {
		t.Fatalf("sources overview: %+v", so.Items)
	}
	var platform, acquisition string
	if err := f.pool.QueryRow(f.ctx, "SELECT inventory_platform,acquisition FROM sources.agents WHERE tenant_id=$1 AND source_id=$2", tenant, agentSource).Scan(&platform, &acquisition); err != nil || platform != "linux/amd64" || acquisition != "ssh" {
		t.Fatal("target agent platform/acquisition", platform, acquisition, err)
	}
	// учётка — только своему collector, по mTLS, с аудитом выдачи
	code, raw = post("/api/v1/machine/collect-targets/"+tg.ID+"/secret", []byte("{}"))
	if code != 200 || !strings.Contains(string(raw), "c51-target-secret") || !strings.Contains(string(raw), `"username":"scanprobe"`) {
		t.Fatalf("secret %d", code)
	}
	if res, err := anon.Post(ms.URL+"/api/v1/machine/collect-targets/"+tg.ID+"/secret", "application/json", strings.NewReader("{}")); err != nil || res.StatusCode != 401 {
		t.Fatal("secret without client certificate", err)
	}
	var issued int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND action='discovery.credential_issued' AND actor_ref=$2", tenant, "collector:"+collector).Scan(&issued)
	if issued != 1 {
		t.Fatal("credential issuance must be audited with the collector as actor", issued)
	}
	// стенд №12, дефект 5: «Собрать сейчас» — оператор может, повтор раньше 2 минут — 409, collector видит запрос
	var cn sources.RemoteTarget
	_ = json.Unmarshal(call("op51", "POST", "/api/v1/discovery/targets/"+tg.ID+"/collect", `{}`, 202), &cn)
	if cn.CollectAt == nil {
		t.Fatalf("collect request %+v", cn)
	}
	call("op51", "POST", "/api/v1/discovery/targets/"+tg.ID+"/collect", `{}`, 409)
	call("view51", "POST", "/api/v1/discovery/targets/"+tg.ID+"/collect", `{}`, 403)
	if code, raw = post("/api/v1/machine/collect-targets", []byte("{}")); code != 200 || !strings.Contains(string(raw), `"collect_requested_at":"`) {
		t.Fatalf("collector must see the collect request: %d %s", code, raw)
	}
	// стенд №12: источник отключённой цели — на паузе (без предупреждений о контакте); после включения — снова в учёте
	paused := func() bool {
		t.Helper()
		items, err := machine.Diagnostics(f.ctx, f.identity)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range items {
			if d.Source == agentSource {
				return d.Paused
			}
		}
		t.Fatal("target source missing from diagnostics")
		return false
	}
	if paused() {
		t.Fatal("active target source must not be paused")
	}
	var dis sources.RemoteTarget
	_ = json.Unmarshal(call("admin", "PATCH", "/api/v1/discovery/targets/"+tg.ID, `{"revision":"`+tl.Items[0].Revision+`","disabled":true}`, 200), &dis)
	if !paused() {
		t.Fatal("disabled target source must be paused")
	}
	var re sources.RemoteTarget
	_ = json.Unmarshal(call("admin", "PATCH", "/api/v1/discovery/targets/"+tg.ID, `{"revision":"`+dis.Revision+`","disabled":false}`, 200), &re)
	if re.State != "pending" || re.Source != nil { // №56: включение — заново через регистрацию (личность цели живёт сутки)
		t.Fatalf("re-enabled target must re-register: state=%s source=%v", re.State, re.Source)
	}
	if paused() {
		t.Fatal("re-enabled target source must not be paused")
	}
	// SSH-цель без отпечатка: collector запоминает ключ при первом подключении; смена ключа — 409; сброс из Web
	var tofu sources.RemoteTarget
	_ = json.Unmarshal(call("admin", "POST", "/api/v1/discovery/targets", strings.Replace(target51(""), "10.51.0.10", "10.51.0.30", 1), 201), &tofu)
	if tofu.HostKey != nil || tofu.HostKeyOrigin != nil {
		t.Fatalf("target without fingerprint %+v", tofu)
	}
	firstKey, otherKey := "SHA256:"+strings.Repeat("B", 43), "SHA256:"+strings.Repeat("C", 43)
	if code, _ = post("/api/v1/machine/collect-targets/"+tofu.ID+"/hostkey", []byte(`{"host_key_sha256":"`+firstKey+`"}`)); code != 204 {
		t.Fatal("pin on first use", code)
	}
	if code, _ = post("/api/v1/machine/collect-targets/"+tofu.ID+"/hostkey", []byte(`{"host_key_sha256":"`+firstKey+`"}`)); code != 204 {
		t.Fatal("same key again", code)
	}
	if code, _ = post("/api/v1/machine/collect-targets/"+tofu.ID+"/hostkey", []byte(`{"host_key_sha256":"`+otherKey+`"}`)); code != 409 {
		t.Fatal("changed host key must be refused", code)
	}
	_ = json.Unmarshal(call("view51", "GET", "/api/v1/discovery/targets", "", 200), &tl)
	for _, x := range tl.Items {
		if x.ID == tofu.ID {
			tofu = x
		}
	}
	if tofu.HostKey == nil || *tofu.HostKey != firstKey || tofu.HostKeyOrigin == nil || *tofu.HostKeyOrigin != "first_use" || tofu.LastError == nil || *tofu.LastError != "host_key_changed" {
		t.Fatalf("pinned target %+v", tofu)
	}
	_ = json.Unmarshal(call("admin", "PATCH", "/api/v1/discovery/targets/"+tofu.ID, `{"revision":"`+tofu.Revision+`","disabled":false,"reset_host_key":true}`, 200), &tofu)
	if tofu.HostKey != nil || tofu.LastError != nil {
		t.Fatalf("reset host key %+v", tofu)
	}
	// WinRM-цель без PEM: collector запоминает сертификат сервера при первом подключении; смена — 409 cert_changed;
	// сброс из Web. PEM без имени ПК — отказ (имя нужно для проверки сертификата по CA).
	var wcred sources.CollectCredential
	_ = json.Unmarshal(call("admin", "POST", "/api/v1/discovery/credentials", `{"name":"Windows RO","kind":"winrm","username":"AWM\\scan","secret":{"password":"winrm-secret-51"}}`, 201), &wcred)
	call("admin", "POST", "/api/v1/discovery/targets", fmt.Sprintf(`{"collector_id":%q,"address":"10.51.0.31","kind":"winrm","credential_id":%q,"tls_ca_pem":"-----BEGIN CERTIFICATE-----"}`, collector, wcred.ID), 422)
	var wt sources.RemoteTarget
	_ = json.Unmarshal(call("admin", "POST", "/api/v1/discovery/targets", fmt.Sprintf(`{"collector_id":%q,"address":"10.51.0.31","kind":"winrm","credential_id":%q}`, collector, wcred.ID), 201), &wt)
	if wt.Port != 5986 || wt.CertSHA256 != nil || wt.CertOrigin != nil || wt.ServerName != nil {
		t.Fatalf("winrm target without PEM %+v", wt)
	}
	firstCert, otherCert := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if code, _ = post("/api/v1/machine/collect-targets/"+wt.ID+"/tlscert", []byte(`{"tls_cert_sha256":"`+firstCert+`"}`)); code != 204 {
		t.Fatal("certificate pin on first use", code)
	}
	if code, _ = post("/api/v1/machine/collect-targets/"+wt.ID+"/tlscert", []byte(`{"tls_cert_sha256":"`+otherCert+`"}`)); code != 409 {
		t.Fatal("changed certificate must be refused", code)
	}
	if code, _ = post("/api/v1/machine/collect-targets/"+tofu.ID+"/tlscert", []byte(`{"tls_cert_sha256":"`+firstCert+`"}`)); code != 404 {
		t.Fatal("certificate pin is only for winrm targets without PEM", code)
	}
	_ = json.Unmarshal(call("view51", "GET", "/api/v1/discovery/targets", "", 200), &tl)
	for _, x := range tl.Items {
		if x.ID == wt.ID {
			wt = x
		}
	}
	if wt.CertSHA256 == nil || *wt.CertSHA256 != firstCert || wt.CertOrigin == nil || *wt.CertOrigin != "first_use" || wt.LastError == nil || *wt.LastError != "cert_changed" {
		t.Fatalf("pinned winrm target %+v", wt)
	}
	_ = json.Unmarshal(call("admin", "PATCH", "/api/v1/discovery/targets/"+wt.ID, `{"revision":"`+wt.Revision+`","disabled":false,"reset_tls_cert":true}`, 200), &wt)
	if wt.CertSHA256 != nil || wt.CertOrigin != nil || wt.LastError != nil {
		t.Fatalf("reset certificate %+v", wt)
	}
	// «CA домена»: без заданного CA цель с этим режимом не создаётся; не-CA сертификат не принимается; collector
	// получает CA домена в описании цели; закрепление сертификата для такой цели невозможно; пока цели есть — CA
	// удалить нельзя (409)
	var trust sources.WinRMTrust
	_ = json.Unmarshal(call("admin", "GET", "/api/v1/discovery/winrm-ca", "", 200), &trust)
	if trust.Configured || trust.Revision != "0" {
		t.Fatalf("empty domain CA %+v", trust)
	}
	call("view51", "GET", "/api/v1/discovery/winrm-ca", "", 403)
	domainTarget := fmt.Sprintf(`{"collector_id":%q,"address":"10.51.0.32","kind":"winrm","credential_id":%q,"tls_trust":"domain_ca","tls_server_name":"win-32.awm.local"}`, collector, wcred.ID)
	call("admin", "POST", "/api/v1/discovery/targets", domainTarget, 422)
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(51), Subject: pkix.Name{CommonName: "AWM Root CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(52), Subject: pkix.Name{CommonName: "leaf"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &caKey.PublicKey, caKey)
	leafJSON, _ := json.Marshal(map[string]any{"revision": "0", "ca_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))})
	call("admin", "PUT", "/api/v1/discovery/winrm-ca", string(leafJSON), 422)
	caJSON, _ := json.Marshal(map[string]any{"revision": "0", "ca_pem": caPEM})
	_ = json.Unmarshal(call("admin", "PUT", "/api/v1/discovery/winrm-ca", string(caJSON), 200), &trust)
	if !trust.Configured || trust.Revision != "1" || len(trust.Certificates) != 1 || !strings.Contains(trust.Certificates[0].Subject, "AWM Root CA") {
		t.Fatalf("domain CA %+v", trust)
	}
	call("admin", "PUT", "/api/v1/discovery/winrm-ca", string(caJSON), 412)
	call("admin", "POST", "/api/v1/discovery/targets", strings.Replace(domainTarget, `,"tls_server_name":"win-32.awm.local"`, "", 1), 422)
	var dt sources.RemoteTarget
	_ = json.Unmarshal(call("admin", "POST", "/api/v1/discovery/targets", domainTarget, 201), &dt)
	if dt.CertOrigin == nil || *dt.CertOrigin != "domain_ca" || dt.CertSHA256 != nil {
		t.Fatalf("domain CA target %+v", dt)
	}
	code, raw = post("/api/v1/machine/collect-targets", []byte("{}"))
	var machineTargets struct {
		Items []sources.MachineTarget `json:"items"`
	}
	_ = json.Unmarshal(raw, &machineTargets)
	gotCA := false
	for _, x := range machineTargets.Items {
		if x.ID == dt.ID && x.CAPEM != nil && *x.CAPEM == caPEM && x.CertOrigin != nil && *x.CertOrigin == "domain_ca" {
			gotCA = true
		}
	}
	if code != 200 || !gotCA {
		t.Fatalf("collector must receive the domain CA for the target: %d %s", code, raw)
	}
	if code, _ = post("/api/v1/machine/collect-targets/"+dt.ID+"/tlscert", []byte(`{"tls_cert_sha256":"`+firstCert+`"}`)); code != 404 {
		t.Fatal("domain CA target must not be pinned", code)
	}
	call("admin", "PUT", "/api/v1/discovery/winrm-ca", `{"revision":"1","ca_pem":null}`, 409)
	// WinRM HTTP 5985 + Kerberos: только по полному имени ПК, без сертификатов; запоминание сертификата не применяется
	kerberosTarget := fmt.Sprintf(`{"collector_id":%q,"address":"10.51.0.33","kind":"winrm","credential_id":%q,"winrm_transport":"http_kerberos"%%s}`, collector, wcred.ID)
	for _, bad := range []string{"", `,"tls_server_name":"10.51.0.33"`, `,"tls_server_name":"win-33"`, `,"tls_server_name":"win-33.awm.local","tls_ca_pem":"x"`, `,"tls_server_name":"win-33.awm.local","tls_trust":"domain_ca"`} {
		call("admin", "POST", "/api/v1/discovery/targets", fmt.Sprintf(kerberosTarget, bad), 422)
	}
	call("admin", "POST", "/api/v1/discovery/targets", fmt.Sprintf(`{"collector_id":%q,"address":"10.51.0.34","kind":"winrm","credential_id":%q,"winrm_transport":"http_ntlm","tls_server_name":"win-34.awm.local"}`, collector, wcred.ID), 422)
	var kt sources.RemoteTarget
	_ = json.Unmarshal(call("admin", "POST", "/api/v1/discovery/targets", fmt.Sprintf(kerberosTarget, `,"tls_server_name":"win-33.awm.local"`), 201), &kt)
	if kt.Port != 5985 || kt.Transport == nil || *kt.Transport != "http_kerberos" || kt.CertOrigin != nil || kt.ServerName == nil || *kt.ServerName != "win-33.awm.local" {
		t.Fatalf("kerberos target %+v", kt)
	}
	if wt.Transport == nil || *wt.Transport != "https" {
		t.Fatalf("https is the default winrm transport %+v", wt)
	}
	if code, _ = post("/api/v1/machine/collect-targets/"+kt.ID+"/tlscert", []byte(`{"tls_cert_sha256":"`+firstCert+`"}`)); code != 404 {
		t.Fatal("kerberos target has no certificate to pin", code)
	}
	var pinAudit int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND action IN ('discovery.target_tls_cert_pinned','discovery.target_tls_cert_reset')", tenant).Scan(&pinAudit)
	if pinAudit != 2 {
		t.Fatal("certificate pin and reset must be audited", pinAudit)
	}
	// SNMPv3-цель сетевого устройства: без отпечатка/сертификата, источник регистрируется с платформой network/snmp
	var scred sources.CollectCredential
	_ = json.Unmarshal(call("admin", "POST", "/api/v1/discovery/credentials", `{"name":"SNMP core","kind":"snmp","username":"surveyscan","secret":{"auth_protocol":"SHA256","auth_key":"auth-key-51","priv_protocol":"AES","priv_key":"priv-key-51"}}`, 201), &scred)
	call("admin", "POST", "/api/v1/discovery/targets", fmt.Sprintf(`{"collector_id":%q,"address":"10.51.0.20","kind":"snmp","credential_id":%q,"host_key_sha256":"%s"}`, collector, scred.ID, hostKey), 422)
	var st sources.RemoteTarget
	_ = json.Unmarshal(call("admin", "POST", "/api/v1/discovery/targets", fmt.Sprintf(`{"collector_id":%q,"address":"10.51.0.20","kind":"snmp","credential_id":%q}`, collector, scred.ID), 201), &st)
	if st.Port != 161 {
		t.Fatal("snmp port", st.Port)
	}
	snmpSource := identifier.New()
	_, snmpHash, _, _ := csrTLSMaterial(t)
	snmpPub, _, _ := ed25519.GenerateKey(rand.Reader)
	body, _ := json.Marshal(sources.TargetGrantRequest{Source: snmpSource, CSRHash: snmpHash, Public: base64.RawURLEncoding.EncodeToString(snmpPub)})
	if code, raw = post("/api/v1/machine/collect-targets/"+st.ID+"/grant", body); code != 200 {
		t.Fatalf("snmp grant %d %s", code, raw)
	}
	if err := f.pool.QueryRow(f.ctx, "SELECT inventory_platform,acquisition FROM sources.agents WHERE tenant_id=$1 AND source_id=$2", tenant, snmpSource).Scan(&platform, &acquisition); err != nil || platform != "network/snmp" || acquisition != "snmp" {
		t.Fatal("snmp target agent platform/acquisition", platform, acquisition, err)
	}
	if code, raw = post("/api/v1/machine/collect-targets/"+st.ID+"/secret", []byte("{}")); code != 200 || !strings.Contains(string(raw), "priv-key-51") {
		t.Fatalf("snmp secret %d", code)
	}
	_ = json.Unmarshal(call("admin", "PATCH", "/api/v1/discovery/targets/"+tg.ID, `{"revision":"`+tl.Items[0].Revision+`","disabled":true}`, 200), &tg)
	if code, _ = post("/api/v1/machine/collect-targets/"+tg.ID+"/secret", []byte("{}")); code != 404 {
		t.Fatal("disabled target must not receive the credential", code)
	}
	// расписание: подсеть с периодом 60 мин и последним запуском только что — не ставится
	tx, _ := f.pool.Begin(f.ctx)
	k, err := sources.Store{}.DiscoveryDue(f.ctx, tx, tenant)
	tx.Rollback(f.ctx)
	if err != nil || k != 0 {
		t.Fatal("schedule must respect the period", k, err)
	}
	// C57.01: снимок платформы от того же collector — подпись его ключом, чужой ключ — отказ, повтор — без дублей
	c57, err := os.ReadFile("../../contracts/c57-platform.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc57, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(c57)))
	if err = compiler.AddResource("urn:surveyscan:c57:platform:1:0", doc57); err != nil {
		t.Fatal(err)
	}
	valid57 := func(def string, raw []byte) {
		t.Helper()
		schema, err := compiler.Compile("urn:surveyscan:c57:platform:1:0#/$defs/" + def)
		if err != nil {
			t.Fatal(err)
		}
		instance, err := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
		if err != nil || schema.Validate(instance) != nil {
			t.Fatalf("%s violates contract: %v %s", def, schema.Validate(instance), raw)
		}
	}
	snapshotID := identifier.New()
	platformBody := func(key ed25519.PrivateKey) []byte {
		payload, _ := json.Marshal(map[string]any{"major": 1, "snapshot_id": snapshotID, "tenant_id": tenant, "source_id": collector, "generation_id": enrolled.GenerationID,
			"target_id": nil, "platform": "kvm", "instance": "kvm01.example", "instance_name": "kvm01", "collected_at": time.Now().UTC().Format(time.RFC3339Nano), "complete": true,
			"objects": []map[string]any{{"ref": "host", "kind": "host", "name": "kvm01", "bios_uuid": nil, "serial": nil, "hostname": "kvm01.example", "macs": []string{}, "attrs": map[string]any{"cpus": 8}},
				{"ref": "vm-web", "kind": "vm", "name": "web", "bios_uuid": "4c4c4544-0042-3110-8030-b4c04f4e3332", "serial": nil, "hostname": nil, "macs": []string{"52:54:00:12:34:56"}, "attrs": map[string]any{"state": "running", "vcpu": 2}}},
			"relations": []map[string]any{{"from": "vm-web", "type": "runs_on", "to": "host"}}, "errors": []string{}})
		canonical, _ := wire.Canonical(payload)
		sum := sha256.Sum256(canonical)
		sig := ed25519.Sign(key, append([]byte(sources.PlatformSignaturePrefix), canonical...))
		body, _ := json.Marshal(map[string]any{"payload": json.RawMessage(payload), "payload_sha256": hex.EncodeToString(sum[:]), "key_id": enrolled.KeyID, "signature": base64.RawURLEncoding.EncodeToString(sig)})
		valid57("SignedPlatformSnapshot", body)
		return body
	}
	if code, _ := post("/api/v1/machine/platform-snapshots", platformBody(foreign)); code != 400 {
		t.Fatalf("snapshot signed by another key: %d", code)
	}
	code, raw = post("/api/v1/machine/platform-snapshots", platformBody(signKey))
	valid57("PlatformSnapshotResult", raw)
	if code != 200 || !strings.Contains(string(raw), `"duplicate":false`) || !strings.Contains(string(raw), `"objects":2`) {
		t.Fatalf("snapshot %d %s", code, raw)
	}
	if code, raw = post("/api/v1/machine/platform-snapshots", platformBody(signKey)); code != 200 || !strings.Contains(string(raw), `"duplicate":true`) {
		t.Fatalf("repeat %d %s", code, raw)
	}
	instances := call("view51", "GET", "/api/v1/platforms", "", 200)
	valid57("PlatformInstancePage", instances)
	var ip struct {
		Items []struct {
			ID string `json:"instance_id"`
		} `json:"items"`
	}
	if json.Unmarshal(instances, &ip) != nil || len(ip.Items) != 1 {
		t.Fatalf("instances %s", instances)
	}
	valid57("PlatformObjectPage", call("view51", "GET", "/api/v1/platforms/"+ip.Items[0].ID+"/objects?kind=vm", "", 200))
	unmatched := call("view51", "GET", "/api/v1/platforms/"+ip.Items[0].ID+"/objects?unmatched=true", "", 200)
	if !strings.Contains(string(unmatched), `"total":2`) {
		t.Fatalf("unmatched hosts and vms %s", unmatched)
	}
	call("view51", "GET", "/api/v1/platforms/"+ip.Items[0].ID+"/objects?kind=bogus", "", 422)
	// C57.03: цель vSphere — учётка vsphere (только пароль), порт 443, без источника-агента (grant не выдаётся);
	// сертификат запоминается при первом подключении, смена — 409; первый успешный отчёт — цель активна
	var vcred sources.CollectCredential
	_ = json.Unmarshal(call("admin", "POST", "/api/v1/discovery/credentials", `{"name":"vCenter RO","kind":"vsphere","username":"ro@vsphere.local","secret":{"password":"vsphere-secret-57"}}`, 201), &vcred)
	call("admin", "POST", "/api/v1/discovery/credentials", `{"name":"vCenter key","kind":"vsphere","username":"ro","secret":{"private_key":"-----BEGIN OPENSSH PRIVATE KEY-----"}}`, 422)
	call("admin", "POST", "/api/v1/discovery/targets", fmt.Sprintf(`{"collector_id":%q,"address":"10.51.0.40","kind":"vsphere","credential_id":%q,"tls_trust":"domain_ca"}`, collector, vcred.ID), 422)
	call("admin", "POST", "/api/v1/discovery/targets", fmt.Sprintf(`{"collector_id":%q,"address":"10.51.0.40","kind":"vsphere","credential_id":%q}`, collector, wcred.ID), 422)
	var vt sources.RemoteTarget
	_ = json.Unmarshal(call("admin", "POST", "/api/v1/discovery/targets", fmt.Sprintf(`{"collector_id":%q,"address":"10.51.0.40","kind":"vsphere","credential_id":%q}`, collector, vcred.ID), 201), &vt)
	if vt.Port != 443 || vt.State != "pending" || vt.Transport != nil || vt.CertSHA256 != nil {
		t.Fatalf("vsphere target %+v", vt)
	}
	if code, raw = post("/api/v1/machine/collect-targets", []byte("{}")); code != 200 || !strings.Contains(string(raw), `"kind":"vsphere"`) {
		t.Fatalf("collector must see the vsphere target: %d", code)
	}
	if code, _ = post("/api/v1/machine/collect-targets/"+vt.ID+"/grant", []byte(`{"source_id":"`+identifier.New()+`","csr_sha256":"`+strings.Repeat("0", 64)+`","signing_public_key":"x"}`)); code == 200 {
		t.Fatal("vsphere target must not get an agent grant")
	}
	if code, _ = post("/api/v1/machine/collect-targets/"+vt.ID+"/tlscert", []byte(`{"tls_cert_sha256":"`+firstCert+`"}`)); code != 204 {
		t.Fatal("vsphere certificate pin on first use", code)
	}
	if code, _ = post("/api/v1/machine/collect-targets/"+vt.ID+"/tlscert", []byte(`{"tls_cert_sha256":"`+otherCert+`"}`)); code != 409 {
		t.Fatal("changed vsphere certificate must be refused", code)
	}
	if code, raw = post("/api/v1/machine/collect-targets/"+vt.ID+"/secret", []byte("{}")); code != 200 || !strings.Contains(string(raw), `"password":"vsphere-secret-57"`) {
		t.Fatal("vsphere secret must be issued to its collector", code)
	}
	if code, _ = post("/api/v1/machine/collect-targets/"+vt.ID+"/report", []byte(`{"ok":true,"problem":""}`)); code != 204 {
		t.Fatal("vsphere report", code)
	}
	_ = json.Unmarshal(call("view51", "GET", "/api/v1/discovery/targets", "", 200), &tl)
	for _, x := range tl.Items {
		if x.ID == vt.ID {
			vt = x
		}
	}
	if vt.State != "active" || vt.Source != nil || vt.CertOrigin == nil || *vt.CertOrigin != "first_use" || vt.LastCollected == nil {
		t.Fatalf("vsphere target after first snapshot %+v", vt)
	}
}

// C51.03 (A): учётки сбора — вводит только администратор, секрет уходит в хранилище секретов и нигде не
// возвращается (ни в ответе, ни в списке, ни в аудите); без хранилища секретов учётка не сохраняется.
func TestC51CollectCredentialsSecretNeverReturned(t *testing.T) {
	f := registrySetup(t)
	if err := f.users.Provision(f.ctx, false, tenant, "", "op51c", password, "operator"); err != nil {
		t.Fatal(err)
	}
	auth, err := access.NewHTTP(f.users, "https://ui.example", false)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := app.NewHTTP(auth, health.Handler(func(context.Context) error { return nil }), f.registry)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	sessions51 := map[string]c31Client{}
	call := func(user, method, path, body string, want int) []byte {
		t.Helper()
		b, ok := sessions51[user]
		if !ok {
			b.b = newBrowser(t, srv)
			b.csrf = b.b.login(t, user).CSRFToken
			sessions51[user] = b
		}
		csrf, origin := b.csrf, "https://ui.example"
		if method == "GET" {
			csrf, origin = "", ""
		}
		code, raw, _ := b.b.request(t, method, path, body, csrf, origin, nil)
		if code != want {
			t.Fatalf("%s %s %s: want %d, got %d %s", user, method, path, want, code, raw)
		}
		return raw
	}
	const secret = "C51-very-secret-pass"
	ssh := `{"name":"Linux только чтение","kind":"ssh","username":"scanprobe","secret":{"password":"` + secret + `"}}`
	call("admin", "POST", "/api/v1/discovery/credentials", ssh, 409) // хранилища секретов нет — не сохраняем
	store := t.TempDir()
	f.registry.Secrets = app.FileSecrets{Dir: store}
	call("op51c", "POST", "/api/v1/discovery/credentials", ssh, 403)
	call("op51c", "GET", "/api/v1/discovery/credentials", "", 403)
	for _, bad := range []string{
		`{"name":"x","kind":"ssh","username":"u","secret":{}}`,
		`{"name":"x","kind":"ssh","username":"u","secret":{"password":"a","private_key":"-----BEGIN OPENSSH PRIVATE KEY-----"}}`,
		`{"name":"x","kind":"winrm","username":"u","secret":{"private_key":"k"}}`,
		`{"name":"x","kind":"snmp","username":"u","secret":{"auth_protocol":"MD5","auth_key":"12345678","priv_protocol":"AES","priv_key":"12345678"}}`,
		`{"name":"x","kind":"telnet","username":"u","secret":{"password":"a"}}`,
	} {
		call("admin", "POST", "/api/v1/discovery/credentials", bad, 422)
	}
	created := call("admin", "POST", "/api/v1/discovery/credentials", ssh, 201)
	var c sources.CollectCredential
	_ = json.Unmarshal(created, &c)
	call("admin", "POST", "/api/v1/discovery/credentials", ssh, 409) // то же название
	call("admin", "POST", "/api/v1/discovery/credentials", `{"name":"SNMP ядро","kind":"snmp","username":"surveyscan","secret":{"auth_protocol":"SHA256","auth_key":"auth-key-123","priv_protocol":"AES","priv_key":"priv-key-123"}}`, 201)
	list := call("admin", "GET", "/api/v1/discovery/credentials", "", 200)
	changed := call("admin", "PATCH", "/api/v1/discovery/credentials/"+c.ID, `{"revision":"1","secret":{"password":"`+secret+`-2"}}`, 200)
	call("admin", "PATCH", "/api/v1/discovery/credentials/"+c.ID, `{"revision":"1","name":"другое"}`, 412)
	for _, raw := range [][]byte{created, list, changed} {
		if strings.Contains(string(raw), secret) || strings.Contains(string(raw), "password") || strings.Contains(string(raw), "priv-key") {
			t.Fatalf("secret leaked into the API: %s", raw)
		}
	}
	stored, ok, err := f.registry.Secrets.Get(f.ctx, tenant, sources.CredentialSecretKey(c.ID))
	if err != nil || !ok || !strings.Contains(string(stored), secret+"-2") {
		t.Fatal("secret must be stored (and rotated) in the secret store", ok, err)
	}
	var leaked int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND (action LIKE 'discovery.credential%') AND row_to_json(audit_events)::text LIKE '%'||$2||'%'", tenant, secret).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatal("secret in audit", leaked, err)
	}
	var audits int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND action IN ('discovery.credential_created','discovery.credential_secret_changed')", tenant).Scan(&audits)
	if audits != 3 {
		t.Fatal("credential creation and secret change audited", audits)
	}
}
