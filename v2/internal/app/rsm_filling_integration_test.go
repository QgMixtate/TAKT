//go:build integration

package app_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/cmdb"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

// C54.02: наполнение РСМ — правила по маске имени (предложение и auto), подтверждение/отклонение (отклонённое
// больше не предлагается), конфликт двух auto-правил уходит в разбор, повторный проход идемпотентен, массовая
// привязка, импорт CSV с предпросмотром (ничего не меняет) и применением (создаёт среду и компонент).
func TestC54RSMFilling(t *testing.T) {
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
	q := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if e := f.pool.QueryRow(ctx, sql, args...).Scan(&n); e != nil {
			t.Fatal(sql, e)
		}
		return n
	}

	var app, web, db cmdb.Component
	inTx(func(tx pgx.Tx) error {
		erpName, billName := "1С:ERP", "Биллинг"
		erp, e := store.CreateService(ctx, tx, tenant, "test", cmdb.ServiceInput{Name: &erpName})
		if e != nil {
			return e
		}
		bill, e := store.CreateService(ctx, tx, tenant, "test", cmdb.ServiceInput{Name: &billName})
		if e != nil {
			return e
		}
		prod, e := store.CreateEnvironment(ctx, tx, tenant, "test", erp.UID, "prod", "Прод")
		if e != nil {
			return e
		}
		bprod, e := store.CreateEnvironment(ctx, tx, tenant, "test", bill.UID, "prod", "Прод")
		if e != nil {
			return e
		}
		if app, e = store.CreateComponent(ctx, tx, tenant, "test", prod.ID, "Сервер приложений", true, nil); e != nil {
			return e
		}
		if db, e = store.CreateComponent(ctx, tx, tenant, "test", prod.ID, "СУБД", true, nil); e != nil {
			return e
		}
		web, e = store.CreateComponent(ctx, tx, tenant, "test", bprod.ID, "Веб", false, nil)
		return e
	})
	// правила: проверка образцов
	for _, bad := range [][2]string{{"subnet", "10.0.0.0/33"}, {"hostname_glob", "msk app"}, {"asset_class", "toaster"}, {"ad_ou", "OU=Servers"}} {
		tx, _ := f.pool.Begin(ctx)
		if _, e := store.CreateRule(ctx, tx, tenant, "test", app.ID, bad[0], bad[1], ""); !errors.Is(e, domain.Invalid) {
			t.Fatalf("rule %v must be invalid: %v", bad, e)
		}
		tx.Rollback(ctx)
	}
	inTx(func(tx pgx.Tx) error {
		if _, e := store.CreateRule(ctx, tx, tenant, "test", app.ID, "hostname_glob", "MSK1-APP-*", "propose"); e != nil {
			return e
		}
		if _, e := store.CreateRule(ctx, tx, tenant, "test", web.ID, "hostname_glob", "msk1-web-*", "auto"); e != nil {
			return e
		}
		_, e := store.CreateRule(ctx, tx, tenant, "test", app.ID, "hostname_glob", "*-x", "auto")
		return e
	})

	// приём наблюдений сам применяет правила
	app1, app2, web1, webx, db1 := host("msk1-app-01"), host("msk1-app-02.corp.local"), host("msk1-web-01"), host("msk1-web-x"), host("msk1-db-01")
	if n := q("SELECT count(*) FROM cmdb.bindings WHERE tenant_id=$1 AND component_id=$2 AND status='proposed' AND origin='rule' AND asset_uid IN ($3,$4)", tenant, app.ID, app1, app2); n != 2 {
		t.Fatalf("app hosts must be proposed (incl. FQDN by short name), got %d", n)
	}
	if n := q("SELECT count(*) FROM cmdb.bindings WHERE tenant_id=$1 AND component_id=$2 AND asset_uid=$3 AND status='active' AND is_primary AND rule_id IS NOT NULL", tenant, web.ID, web1); n != 1 {
		t.Fatalf("auto rule must bind web host as primary, got %d", n)
	}
	if n := q("SELECT count(*) FROM cmdb.bindings WHERE tenant_id=$1 AND asset_uid=$2 AND status='proposed'", tenant, webx); n != 2 {
		t.Fatalf("two auto rules on one host must go to review as proposals, got %d", n)
	}
	if n := q("SELECT count(*) FROM cmdb.bindings WHERE tenant_id=$1 AND asset_uid=$2", tenant, db1); n != 0 {
		t.Fatalf("unmatched host must stay unbound, got %d", n)
	}

	// подтверждение и отклонение
	var p1, p2 string
	inTx(func(tx pgx.Tx) error {
		list, e := store.Proposals(ctx, tx, tenant, 0)
		if e != nil {
			return e
		}
		for _, b := range list {
			if b.AssetUID == app1 {
				p1 = b.ID
			}
			if b.AssetUID == app2 {
				p2 = b.ID
			}
		}
		b, e := store.Confirm(ctx, tx, tenant, "test", p1)
		if e == nil && (b.Status != "active" || !b.Primary) {
			e = errors.New("confirmed proposal must be active and primary")
		}
		if e != nil {
			return e
		}
		return store.Reject(ctx, tx, tenant, "test", p2)
	})
	inTx(func(tx pgx.Tx) error {
		if _, e := store.Confirm(ctx, tx, tenant, "test", p1); !errors.Is(e, domain.NotFound) {
			return errors.New("confirming twice must be NotFound")
		}
		return nil
	})
	// повторный проход: отклонённое не предлагается снова, ничего нового
	res, err := f.registry.ApplyRSMRules(ctx, f.identity, nil)
	if err != nil || res.Bound != 0 || res.Proposed != 0 || res.Assets < 5 {
		t.Fatalf("rerun must be idempotent: %+v %v", res, err)
	}
	if n := q("SELECT count(*) FROM cmdb.bindings WHERE tenant_id=$1 AND asset_uid=$2 AND valid_to IS NULL", tenant, app2); n != 0 {
		t.Fatalf("rejected pair must not be proposed again, got %d", n)
	}

	// массовая привязка
	bulk, err := f.registry.BulkBind(ctx, f.identity, db.ID, []string{db1, web1, identifier.New(), db1})
	if err != nil || bulk.Bound != 2 || bulk.Missing != 1 || bulk.Existing != 0 {
		t.Fatalf("bulk bind: %+v %v", bulk, err)
	}
	if bulk, err = f.registry.BulkBind(ctx, f.identity, db.ID, []string{db1, web1}); err != nil || bulk.Existing != 2 || bulk.Bound != 0 {
		t.Fatalf("bulk bind repeat: %+v %v", bulk, err)
	}

	// импорт CSV: предпросмотр ничего не меняет
	csv := []byte("\uFEFFsurveyscan-rsm-bindings;1\r\nsystem;environment;component;host\r\n" +
		"1С:ERP;Тест;Сервер приложений;msk1-app-01\r\n" +
		"Нет такой;Прод;X;msk1-app-01\r\n" +
		"1С:ERP;Прод;Сервер приложений;no-such-host\r\n" +
		"1С:ERP;Прод;Сервер приложений;msk1-app-0?\r\n" +
		"1С:ERP;Прод;СУБД;" + db1 + "\r\n")
	envs := q("SELECT count(*) FROM cmdb.environments WHERE tenant_id=$1", tenant)
	dry, err := f.registry.ImportRSMCSV(ctx, f.identity, csv, true)
	if err != nil || dry.Counts["will_bind"] != 2 || dry.Counts["system_not_found"] != 1 || dry.Counts["host_not_found"] != 1 || dry.Counts["existing"] != 1 {
		t.Fatalf("dry run: %+v %v", dry.Counts, err)
	}
	if len(dry.Rows[0].Creates) != 2 || q("SELECT count(*) FROM cmdb.environments WHERE tenant_id=$1", tenant) != envs {
		t.Fatalf("dry run must only report creations: %+v", dry.Rows[0])
	}
	applied, err := f.registry.ImportRSMCSV(ctx, f.identity, csv, false)
	if err != nil || applied.Counts["bound"] != 2 || applied.Counts["existing"] != 1 {
		t.Fatalf("apply: %+v %v", applied.Counts, err)
	}
	if n := q("SELECT count(*) FROM cmdb.environments WHERE tenant_id=$1 AND kind='test' AND name='Тест'", tenant); n != 1 {
		t.Fatalf("import must create the test environment, got %d", n)
	}
	if n := q("SELECT count(*) FROM cmdb.bindings WHERE tenant_id=$1 AND origin='import' AND valid_to IS NULL", tenant); n != 2 {
		t.Fatalf("import bindings, got %d", n)
	}
	if _, err := f.registry.ImportRSMCSV(ctx, f.identity, []byte("system;environment;component;host\r\n"), true); !errors.Is(err, domain.Invalid) {
		t.Fatalf("file without format line must be rejected: %v", err)
	}
}
