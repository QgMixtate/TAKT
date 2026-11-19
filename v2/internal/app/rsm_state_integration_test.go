//go:build integration

package app_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/cmdb"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

// C54.03: светофор РСМ на настоящих данных — хосты из приёма наблюдений, эталон компонента (совпадение и
// отсутствие ПО), подъём по дереву, «хосты вне систем»; затем замер на объёме (SURVEYSCAN_RSM_LOAD_HOSTS, по
// умолчанию 3 000 хостов; паспорт крупного enterprise — 100 000 хостов / 2 000 систем — снимается локально).
func TestC54RSMState(t *testing.T) {
	f := registrySetup(t)
	ctx := f.ctx
	store := cmdb.Store{}
	if _, err := f.registry.ConfigureInventoryProtocol12(true); err != nil {
		t.Fatal(err)
	}
	machine := &sources.MachineService{Pool: f.pool, Audit: audit.Store{}}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	source, generation := identifier.New(), identifier.New()
	if _, err := machine.RegisterPortable(ctx, "console", sources.PortableRegistration{Tenant: tenant, Site: siteID, Scope: scopeID, Source: source, Generation: generation, PublicKey: pub}); err != nil {
		t.Fatal(err)
	}
	seq := 0
	host := func(name string) string {
		seq++
		o := testObservation12(t, f, strconv.Itoa(seq))
		o.Origin = contracts.Origin{SourceID: source, SourceKind: "portable", GenerationID: generation}
		o.Record = contracts.SourceRecord{Namespace: "host", LocalID: "host:" + name}
		o.Clock = "estimated"
		o.Candidates = []contracts.Candidate{{Kind: "machine_uuid", Namespace: "linux-machine-id", Value: "4c4c4544-0000-1000-8000-" + identifier.New()[24:]}, {Kind: "hostname", Namespace: "hostname.raw", Value: name}}
		raw, _ := json.Marshal(o)
		report, err := f.registry.ImportPortable(ctx, machine, tenant, source, portablePackage(t, key, source, raw))
		if err != nil || len(report.Records) != 1 || report.Records[0].Disposition != "applied" {
			t.Fatal(err, report)
		}
		return report.Records[0].AssetID
	}
	inTx := func(fn func(pgx.Tx) error) {
		t.Helper()
		tx, e := f.pool.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		if e = fn(tx); e != nil {
			t.Fatal(e)
		}
		if e = tx.Commit(ctx); e != nil {
			t.Fatal(e)
		}
	}
	h1, h2, h3, h4 := host("erp-app-01"), host("erp-app-02"), host("erp-db-01"), host("loose-01")
	var erp cmdb.Service
	var app, db cmdb.Component
	inTx(func(tx pgx.Tx) (e error) {
		name, high := "1С:ERP", "high"
		if erp, e = store.CreateService(ctx, tx, tenant, "test", cmdb.ServiceInput{Name: &name, Criticality: &high}); e != nil {
			return e
		}
		prod, e := store.CreateEnvironment(ctx, tx, tenant, "test", erp.UID, "prod", "Прод")
		if e != nil {
			return e
		}
		if app, e = store.CreateComponent(ctx, tx, tenant, "test", prod.ID, "Сервер приложений", true, json.RawMessage(`{"os":"Windows Server","software":{"Sample":""}}`)); e != nil {
			return e
		}
		if db, e = store.CreateComponent(ctx, tx, tenant, "test", prod.ID, "СУБД", true, json.RawMessage(`{"software":{"PostgreSQL":"16"}}`)); e != nil {
			return e
		}
		for _, b := range [][2]string{{app.ID, h1}, {app.ID, h2}, {db.ID, h3}} {
			if _, e = store.Bind(ctx, tx, tenant, "test", b[0], b[1], "manual", false); e != nil {
				return e
			}
		}
		return nil
	})
	res, err := f.registry.RecomputeRSMState(ctx, tenant)
	if err != nil || res.Hosts != 3 || res.Skipped {
		t.Fatalf("recompute: %+v %v", res, err)
	}
	state := func(uid string) (string, string) {
		var color, reasons string
		if e := f.pool.QueryRow(ctx, "SELECT color,reasons::text FROM cmdb.host_states WHERE tenant_id=$1 AND asset_uid=$2", tenant, uid).Scan(&color, &reasons); e != nil {
			t.Fatal(uid, e)
		}
		return color, reasons
	}
	c1, r1 := state(h1)
	c3, r3 := state(h3)
	t.Logf("h1=%s %s; h3=%s %s", c1, r1, c3, r3)
	if strings.Contains(r1, "BASELINE") || !strings.Contains(r3, "BASELINE_SOFTWARE_MISSING") || colorWeightTest[c3] < colorWeightTest["yellow"] {
		t.Fatalf("baseline: h1=%s %s h3=%s %s", c1, r1, c3, r3)
	}
	tx, _ := f.pool.Begin(ctx)
	defer tx.Rollback(ctx)
	sys, err := store.Node(ctx, tx, tenant, "system", erp.UID)
	if err != nil || sys.Hosts != 3 || colorWeightTest[sys.Color] < colorWeightTest["yellow"] {
		t.Fatalf("system state: %+v %v", sys, err)
	}
	company, err := store.Node(ctx, tx, tenant, "tenant", tenant)
	if err != nil || company.Unassigned < 1 {
		t.Fatalf("company state: %+v %v", company, err)
	}
	loose, err := store.UnassignedHosts(ctx, tx, tenant, "", 500)
	found := false
	for _, u := range loose {
		found = found || u == h4
	}
	if err != nil || !found {
		t.Fatalf("loose host must be listed as unassigned: %v", err)
	}
	tx.Rollback(ctx)
	// отвязка: состояние хоста убирается следующим проходом
	inTx(func(tx pgx.Tx) error {
		list, e := store.AssetBindings(ctx, tx, tenant, h2)
		if e != nil {
			return e
		}
		return store.Unbind(ctx, tx, tenant, "test", list[0].ID)
	})
	if res, err = f.registry.RecomputeRSMState(ctx, tenant); err != nil || res.Hosts != 2 {
		t.Fatalf("recompute after unbind: %+v %v", res, err)
	}
	var left int
	if e := f.pool.QueryRow(ctx, "SELECT count(*) FROM cmdb.host_states WHERE tenant_id=$1 AND asset_uid=$2", tenant, h2).Scan(&left); e != nil || left != 0 {
		t.Fatalf("unbound host state must be pruned: %d %v", left, e)
	}
	rsmLoad(t, f)
}

var colorWeightTest = map[string]int{"grey": 0, "green": 1, "yellow": 2, "red": 3}

// rsmLoad — замер: N хостов, N/50 систем (среда прод, два компонента), каждый хост в одном компоненте, 5% вне систем.
// Активы и привязки — массовой вставкой (стражи актива — история/аудит/ответственный — на время вставки отключены в той же транзакции).
func rsmLoad(t *testing.T, f *registryFixture) {
	ctx := f.ctx
	n := 3000
	if v, e := strconv.Atoi(os.Getenv("SURVEYSCAN_RSM_LOAD_HOSTS")); e == nil && v > 0 {
		n = v
	}
	systems := max(n/50, 1)
	load := tenant // тенант теста: площадка и сетевая область уже есть
	start := time.Now()
	tx, e := f.pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	steps := []string{
		"ALTER TABLE assets.assets DISABLE TRIGGER USER",
		"ALTER TABLE assets.asset_business_fields DISABLE TRIGGER USER",
		"INSERT INTO assets.assets(tenant_id,asset_uid,site_id,scope_id) SELECT $1,gen_random_uuid(),'" + siteID + "','" + scopeID + "' FROM generate_series(1," + strconv.Itoa(n) + ")",
		"INSERT INTO assets.asset_business_fields(tenant_id,asset_uid,display_name) SELECT tenant_id,asset_uid,'load-'||row_number() OVER (ORDER BY asset_uid) FROM assets.assets WHERE tenant_id=$1 ON CONFLICT DO NOTHING",
		"ALTER TABLE assets.assets ENABLE TRIGGER USER",
		"ALTER TABLE assets.asset_business_fields ENABLE TRIGGER USER",
		"INSERT INTO cmdb.services(tenant_id,service_uid,name,criticality) SELECT $1,gen_random_uuid(),'Нагрузка '||i,(ARRAY['low','medium','high','critical'])[1+i%4] FROM generate_series(1," + strconv.Itoa(systems) + ") i",
		"INSERT INTO cmdb.environments(tenant_id,environment_id,service_uid,kind,name) SELECT $1,gen_random_uuid(),service_uid,'prod','Прод' FROM cmdb.services WHERE tenant_id=$1 AND name LIKE 'Нагрузка %'",
		"INSERT INTO cmdb.components(tenant_id,component_id,environment_id,name,critical) SELECT $1,gen_random_uuid(),environment_id,c.name,c.critical FROM cmdb.environments, (VALUES ('Приложение',true),('Веб',false)) c(name,critical) WHERE tenant_id=$1 AND service_uid IN (SELECT service_uid FROM cmdb.services WHERE tenant_id=$1 AND name LIKE 'Нагрузка %')",
		`WITH c AS (SELECT component_id,row_number() OVER (ORDER BY component_id)-1 AS k FROM cmdb.components WHERE tenant_id=$1 AND name IN ('Приложение','Веб')),
m AS (SELECT count(*) AS m FROM c)
INSERT INTO cmdb.bindings(tenant_id,binding_id,component_id,asset_uid,status,is_primary,origin,actor_ref)
SELECT $1,gen_random_uuid(),c.component_id,a.asset_uid,'active',true,'import','load' FROM
(SELECT asset_uid,row_number() OVER (ORDER BY asset_uid) AS r FROM assets.assets x WHERE tenant_id=$1 AND NOT EXISTS(SELECT 1 FROM cmdb.bindings b WHERE b.tenant_id=x.tenant_id AND b.asset_uid=x.asset_uid)) a
JOIN c ON c.k=a.r%(SELECT m FROM m) WHERE a.r%20<>0`,
	}
	for _, s := range steps {
		args := []any{load}
		if !strings.Contains(s, "$1") {
			args = nil
		}
		if _, e = tx.Exec(ctx, s, args...); e != nil {
			if strings.Contains(s, "ALTER TABLE") && strings.Contains(e.Error(), "owner") {
				t.Skipf("load measurement needs table owner rights for bulk insert: %v", e)
			}
			t.Fatal(s, e)
		}
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	for _, table := range []string{"assets.assets", "cmdb.bindings", "cmdb.components", "cmdb.services"} {
		if _, e = f.pool.Exec(ctx, "ANALYZE "+table); e != nil { // как autovacuum после массовой загрузки
			t.Fatal(e)
		}
	}
	t.Logf("load: %d hosts, %d systems seeded in %s", n, systems, time.Since(start).Round(time.Millisecond))
	res, err := f.registry.RecomputeRSMState(ctx, load)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("load: recompute %d hosts, %d nodes in %s %v", res.Hosts, res.Nodes, res.Duration.Round(time.Millisecond), res.Phases)
	// C53.04: проекция плотного реестра хостов — полный пересчёт (первый — с наблюдаемым классом) и повторный
	hs := time.Now()
	hn, err := f.registry.RecomputeHostRegistry(ctx, load)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("load: host registry first recompute %d hosts in %s", hn, time.Since(hs).Round(time.Millisecond))
	hs = time.Now()
	if _, err = f.registry.RecomputeHostRegistry(ctx, load); err != nil {
		t.Fatal(err)
	}
	t.Logf("load: host registry repeat recompute in %s", time.Since(hs).Round(time.Millisecond))
	if _, e = f.pool.Exec(ctx, "ANALYZE cmdb.host_registry"); e != nil {
		t.Fatal(e)
	}
	store := cmdb.Store{}
	read, _ := f.pool.Begin(ctx)
	defer read.Rollback(ctx)
	var component string
	if e = read.QueryRow(ctx, "SELECT component_id::text FROM cmdb.components WHERE tenant_id=$1 LIMIT 1", load).Scan(&component); e != nil {
		t.Fatal(e)
	}
	measure := func(name string, fn func() error) {
		best := time.Hour
		for i := 0; i < 3; i++ { // лучший из трёх: первый прогон прогревает кэш
			s := time.Now()
			if e := fn(); e != nil {
				t.Fatal(name, e)
			}
			best = min(best, time.Since(s))
		}
		t.Logf("load: %s %s", name, best.Round(time.Microsecond))
		if best > 300*time.Millisecond {
			t.Errorf("%s took %s, target < 300ms", name, best)
		}
	}
	measure("company node", func() error { _, e := store.Node(ctx, read, load, "tenant", load); return e })
	measure("systems page (problems first)", func() error { _, e := store.SystemsByState(ctx, read, load, cmdb.SystemFilter{Limit: 100}); return e })
	measure("systems page filtered", func() error {
		_, e := store.SystemsByState(ctx, read, load, cmdb.SystemFilter{Color: "grey", Limit: 100})
		return e
	})
	measure("component hosts page", func() error { _, e := store.ComponentHostStates(ctx, read, load, component, 0, 100); return e })
	measure("unassigned hosts page", func() error { _, e := store.UnassignedHosts(ctx, read, load, "", 100); return e })
	measure("hosts registry page (name)", func() error {
		_, _, e := store.HostRegistryPage(ctx, read, load, cmdb.HostFilter{Limit: 100})
		return e
	})
	measure("hosts registry page (filter+sort last)", func() error {
		_, _, e := store.HostRegistryPage(ctx, read, load, cmdb.HostFilter{Query: "load-1", Sort: "last", Desc: true, Limit: 500})
		return e
	})
	measure("hosts registry counters", func() error { _, e := store.HostRegistryCounters(ctx, read, load); return e })
	measure("hosts registry tree (site)", func() error { _, e := store.HostRegistryTree(ctx, read, load, "site"); return e })
}
