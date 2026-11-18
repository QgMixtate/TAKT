//go:build integration

package app_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/portable"
)

// C23.04: узлы обследования из portable-пакета — в «Найденные узлы» с исходами; активов-пустышек нет; collected —
// со ссылкой на актив; повтор пакета ничего не меняет; старый формат — как раньше.
func TestC2304PortableDiscoveryImport(t *testing.T) {
	f := registrySetup(t)
	if _, err := f.registry.ConfigureInventoryProtocol12(true); err != nil {
		t.Fatal(err)
	}
	machine := &sources.MachineService{Pool: f.pool, Audit: audit.Store{}}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	source, generation := identifier.New(), identifier.New()
	if _, err := machine.RegisterPortable(f.ctx, "console", sources.PortableRegistration{Tenant: tenant, Site: siteID, Scope: scopeID, Source: source, Generation: generation, PublicKey: pub}); err != nil {
		t.Fatal(err)
	}
	o := testObservation12(t, f, "1")
	o.Origin = contracts.Origin{SourceID: source, SourceKind: "portable", GenerationID: generation}
	o.Record = contracts.SourceRecord{Namespace: "host", LocalID: "ssh:10.20.1.15"}
	o.Clock = "estimated"
	raw, _ := json.Marshal(o)
	signed, err := portable.SignObservation(key, raw)
	if err != nil {
		t.Fatal(err)
	}
	var assets int
	count := func() int {
		_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM assets.assets WHERE tenant_id=$1", tenant).Scan(&assets)
		return assets
	}
	before := count()
	doc := []byte(`{"schema_version":{"major":1,"minor":0},"ranges":["10.20.0.0/16"],"excluded":[],"started_at":"2026-11-18T10:00:00Z","finished_at":"2026-11-18T10:05:00Z","complete":true,"hosts":[
{"ip":"10.20.1.15","ports":[22],"kind":"linux_ssh","outcome":"collected","observation_id":"` + o.ID + `"},
{"ip":"10.20.1.40","ports":[5985],"kind":"windows_winrm","outcome":"no_access","reason":"AUTH_FAILED","profile":"domain-ro"},
{"ip":"10.20.1.77","ports":[],"kind":"unknown","outcome":"no_profile"}]}`)
	var buf bytes.Buffer
	if err = portable.WriteWithDiscovery(&buf, key, tenant, source, time.Now(), [][]byte{signed}, doc); err != nil {
		t.Fatal(err)
	}
	report, err := f.registry.ImportPortable(f.ctx, machine, tenant, source, buf.Bytes())
	if err != nil || report.Discovery == nil || report.Discovery.Hosts != 3 || report.Discovery.Collected != 1 || report.Discovery.NoAccess != 1 || report.Discovery.NoProfile != 1 {
		t.Fatal("import report", err, report.Discovery)
	}
	if count() != before+1 {
		t.Fatal("only the collected host may create an asset", before, assets)
	}
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	hosts, err := sources.Store{}.PortableDiscovery(f.ctx, tx, tenant, source, "")
	if err != nil || len(hosts) != 3 || hosts[0].Outcome != "collected" || hosts[0].AssetUID == nil || hosts[1].Reason == nil || *hosts[1].Reason != "AUTH_FAILED" {
		t.Fatal("discovery list", err, hosts)
	}
	if only, _ := (sources.Store{}).PortableDiscovery(f.ctx, tx, tenant, source, "no_access"); len(only) != 1 {
		t.Fatal("outcome filter", only)
	}
	tx.Rollback(f.ctx)
	again, err := f.registry.ImportPortable(f.ctx, machine, tenant, source, buf.Bytes())
	if err != nil || again.Discovery == nil || count() != before+1 {
		t.Fatal("repeat import must not change anything", err)
	}
	var rows int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM sources.portable_discovery_hosts WHERE tenant_id=$1 AND source_id=$2", tenant, source).Scan(&rows)
	if rows != 3 {
		t.Fatal("discovery rows", rows)
	}
}
