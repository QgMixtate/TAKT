//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/cmdb"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

// C54.01: модель РСМ — сервис C26 = система (поля направления, владельца, ответственного ИТ), среды, компоненты с
// эталоном, привязки хостов (общий хост, одна основная, повтор — Conflict), зависимости компонентов, межтенантный
// запрет, перенос привязок при слиянии активов (C25.03).
func TestC54RSMModel(t *testing.T) {
	f := registrySetup(t)
	ctx := f.ctx
	store := cmdb.Store{}
	inTx := func(fn func(pgx.Tx) error) error {
		tx, e := f.pool.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(context.Background())
		if e = fn(tx); e != nil {
			return e
		}
		return tx.Commit(ctx)
	}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	if _, err := f.registry.ConfigureInventoryProtocol12(true); err != nil {
		t.Fatal(err)
	}
	machine := &sources.MachineService{Pool: f.pool, Audit: audit.Store{}}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	source, generation := identifier.New(), identifier.New()
	if _, err := machine.RegisterPortable(ctx, "console", sources.PortableRegistration{Tenant: tenant, Site: siteID, Scope: scopeID, Source: source, Generation: generation, PublicKey: pub}); err != nil {
		t.Fatal(err)
	}
	sequence := 0
	newAsset := func() string {
		sequence++
		o := testObservation12(t, f, strconv.Itoa(sequence))
		o.Origin = contracts.Origin{SourceID: source, SourceKind: "portable", GenerationID: generation}
		o.Record = contracts.SourceRecord{Namespace: "host", LocalID: "rsm-" + strconv.Itoa(sequence)}
		o.Clock = "estimated"
		o.Candidates = []contracts.Candidate{{Kind: "machine_uuid", Namespace: "linux-machine-id", Value: "4c4c4544-0000-1000-8000-" + identifier.New()[24:]}}
		raw, _ := json.Marshal(o)
		report, err := f.registry.ImportPortable(ctx, machine, tenant, source, portablePackage(t, key, source, raw))
		if err != nil || len(report.Records) != 1 || report.Records[0].Disposition != "applied" {
			t.Fatal(err, report)
		}
		return report.Records[0].AssetID
	}

	var dir cmdb.Direction
	var erp, billing cmdb.Service
	must(inTx(func(tx pgx.Tx) (e error) {
		if dir, e = store.CreateDirection(ctx, tx, tenant, "test", "Финансы"); e != nil {
			return e
		}
		name, name2 := "1С:ERP", "Биллинг"
		if erp, e = store.CreateService(ctx, tx, tenant, "test", cmdb.ServiceInput{Name: &name}); e != nil {
			return e
		}
		billing, e = store.CreateService(ctx, tx, tenant, "test", cmdb.ServiceInput{Name: &name2})
		return e
	}))
	if err := inTx(func(tx pgx.Tx) error {
		_, e := store.CreateDirection(ctx, tx, tenant, "test", "финансы")
		return e
	}); !errors.Is(err, domain.Conflict) {
		t.Fatalf("duplicate direction name (case-insensitive) must conflict: %v", err)
	}

	// система: направление и владелец; неверная ревизия — Revision; несуществующее направление — NotFound
	owner, window := "Финансовый департамент", "вс 02:00–06:00"
	var sys cmdb.System
	must(inTx(func(tx pgx.Tx) (e error) {
		sys, e = store.UpdateSystem(ctx, tx, tenant, erp.UID, erp.Revision, "test", cmdb.SystemFields{DirectionUID: &dir.UID, BusinessOwner: &owner, MaintenanceWindow: &window})
		return e
	}))
	if sys.DirectionUID == nil || *sys.DirectionUID != dir.UID || sys.BusinessOwner == nil || *sys.BusinessOwner != owner || sys.Revision == erp.Revision {
		t.Fatalf("system fields not stored: %+v", sys)
	}
	if err := inTx(func(tx pgx.Tx) error {
		_, e := store.UpdateSystem(ctx, tx, tenant, erp.UID, erp.Revision, "test", cmdb.SystemFields{BusinessOwner: &owner})
		return e
	}); !errors.Is(err, domain.Revision) {
		t.Fatalf("stale revision must fail: %v", err)
	}
	ghost := identifier.New()
	if err := inTx(func(tx pgx.Tx) error {
		_, e := store.UpdateSystem(ctx, tx, tenant, erp.UID, sys.Revision, "test", cmdb.SystemFields{DirectionUID: &ghost})
		return e
	}); !errors.Is(err, domain.NotFound) {
		t.Fatalf("unknown direction must be NotFound: %v", err)
	}
	// старый API сервиса C26 видит ту же сущность
	must(inTx(func(tx pgx.Tx) error {
		s, e := store.Service(ctx, tx, tenant, erp.UID)
		if e == nil && s.Name != "1С:ERP" {
			e = errors.New("service view lost")
		}
		return e
	}))

	// среды и компоненты
	var prod, test cmdb.Environment
	var app1c, sql, billDB cmdb.Component
	must(inTx(func(tx pgx.Tx) (e error) {
		if prod, e = store.CreateEnvironment(ctx, tx, tenant, "test", erp.UID, "prod", "Прод"); e != nil {
			return e
		}
		if test, e = store.CreateEnvironment(ctx, tx, tenant, "test", erp.UID, "test", "Тест"); e != nil {
			return e
		}
		baseline := json.RawMessage(`{"os":"Windows Server 2022","software":{"1С:Предприятие":"8.3.24"},"antivirus":"KES 12.6"}`)
		if app1c, e = store.CreateComponent(ctx, tx, tenant, "test", prod.ID, "Сервер приложений 1С", true, baseline); e != nil {
			return e
		}
		if sql, e = store.CreateComponent(ctx, tx, tenant, "test", prod.ID, "СУБД", true, nil); e != nil {
			return e
		}
		billProd, e := store.CreateEnvironment(ctx, tx, tenant, "test", billing.UID, "prod", "Прод")
		if e != nil {
			return e
		}
		billDB, e = store.CreateComponent(ctx, tx, tenant, "test", billProd.ID, "СУБД", false, nil)
		return e
	}))
	if err := inTx(func(tx pgx.Tx) error {
		_, e := store.CreateEnvironment(ctx, tx, tenant, "test", erp.UID, "prod", "прод")
		return e
	}); !errors.Is(err, domain.Conflict) {
		t.Fatalf("duplicate environment name must conflict: %v", err)
	}
	if err := inTx(func(tx pgx.Tx) error {
		_, e := store.CreateEnvironment(ctx, tx, tenant, "test", erp.UID, "qa", "QA")
		return e
	}); !errors.Is(err, domain.Invalid) {
		t.Fatalf("unknown environment kind must be invalid: %v", err)
	}
	if err := inTx(func(tx pgx.Tx) error {
		_, e := store.CreateComponent(ctx, tx, tenant, "test", test.ID, "X", false, json.RawMessage(`[1]`))
		return e
	}); !errors.Is(err, domain.Invalid) {
		t.Fatalf("baseline must be an object: %v", err)
	}

	// привязки: первая — основная; общий хост в двух системах; повтор пары — Conflict; основная одна
	h1, h2, shared := newAsset(), newAsset(), newAsset()
	var b1, bShared1, bShared2 cmdb.Binding
	must(inTx(func(tx pgx.Tx) (e error) {
		if b1, e = store.Bind(ctx, tx, tenant, "test", app1c.ID, h1, "manual", false); e != nil {
			return e
		}
		if _, e = store.Bind(ctx, tx, tenant, "test", app1c.ID, h2, "import", false); e != nil {
			return e
		}
		if bShared1, e = store.Bind(ctx, tx, tenant, "test", sql.ID, shared, "manual", false); e != nil {
			return e
		}
		bShared2, e = store.Bind(ctx, tx, tenant, "test", billDB.ID, shared, "manual", false)
		return e
	}))
	if !b1.Primary || !bShared1.Primary || bShared2.Primary {
		t.Fatalf("primary flags: first=%v shared1=%v shared2=%v", b1.Primary, bShared1.Primary, bShared2.Primary)
	}
	if err := inTx(func(tx pgx.Tx) error {
		_, e := store.Bind(ctx, tx, tenant, "test", app1c.ID, h1, "manual", false)
		return e
	}); !errors.Is(err, domain.Conflict) {
		t.Fatalf("repeated binding must conflict: %v", err)
	}
	// перенос основной на привязку в Биллинге
	must(inTx(func(tx pgx.Tx) error {
		b, e := store.SetPrimary(ctx, tx, tenant, "test", bShared2.ID)
		if e == nil && !b.Primary {
			e = errors.New("binding must become primary")
		}
		return e
	}))
	var primaries int
	must(f.pool.QueryRow(ctx, "SELECT count(*) FROM cmdb.bindings WHERE tenant_id=$1 AND asset_uid=$2 AND valid_to IS NULL AND is_primary", tenant, shared).Scan(&primaries))
	if primaries != 1 {
		t.Fatalf("exactly one primary binding per host, got %d", primaries)
	}
	// снятие основной: основной становится оставшаяся
	must(inTx(func(tx pgx.Tx) error {
		list, e := store.AssetBindings(ctx, tx, tenant, shared)
		if e != nil || len(list) != 2 || !list[0].Primary {
			return errors.New("shared host must have two bindings, primary first")
		}
		return store.Unbind(ctx, tx, tenant, "test", list[0].ID)
	}))
	must(inTx(func(tx pgx.Tx) error {
		list, e := store.AssetBindings(ctx, tx, tenant, shared)
		if e == nil && (len(list) != 1 || !list[0].Primary) {
			e = errors.New("remaining binding must become primary")
		}
		return e
	}))

	// зависимость компонентов; петля — Invalid
	must(inTx(func(tx pgx.Tx) error {
		_, e := store.AddComponentDependency(ctx, tx, tenant, "test", app1c.ID, sql.ID)
		return e
	}))
	if err := inTx(func(tx pgx.Tx) error {
		_, e := store.AddComponentDependency(ctx, tx, tenant, "test", sql.ID, sql.ID)
		return e
	}); !errors.Is(err, domain.Invalid) {
		t.Fatalf("self dependency must be invalid: %v", err)
	}

	// межтенантный запрет: чужой тенант не видит и не может привязать к нашим компонентам
	other := identifier.New()
	if _, e := f.pool.Exec(ctx, "INSERT INTO access.tenants(tenant_id,name,status) VALUES($1,'other','active')", other); e != nil {
		t.Fatal(e)
	}
	if err := inTx(func(tx pgx.Tx) error {
		_, e := store.Bind(ctx, tx, other, "test", app1c.ID, h1, "manual", false)
		return e
	}); !errors.Is(err, domain.NotFound) {
		t.Fatalf("cross-tenant binding must be NotFound: %v", err)
	}
	if err := inTx(func(tx pgx.Tx) error {
		_, e := store.CreateEnvironment(ctx, tx, other, "test", erp.UID, "prod", "Прод")
		return e
	}); !errors.Is(err, domain.NotFound) {
		t.Fatalf("cross-tenant environment must be NotFound: %v", err)
	}

	// слияние: h2 поглощается h1 — привязка h2 к тому же компоненту закрывается как дубль, основная у h1 сохраняется
	if _, err := f.registry.MergeAssets(ctx, f.identity, app.MergeRequest{Target: h1, Absorbed: h2}); err != nil {
		t.Fatal(err)
	}
	var open, dup int
	must(f.pool.QueryRow(ctx, "SELECT count(*) FILTER (WHERE asset_uid=$2 AND valid_to IS NULL), count(*) FILTER (WHERE asset_uid=$3 AND valid_to IS NULL) FROM cmdb.bindings WHERE tenant_id=$1", tenant, h1, h2).Scan(&open, &dup))
	if open != 1 || dup != 0 {
		t.Fatalf("after merge: target open=%d absorbed open=%d", open, dup)
	}
	var retargeted int
	must(f.pool.QueryRow(ctx, "SELECT count(*) FROM cmdb.changes WHERE tenant_id=$1 AND object_type='binding' AND action='retargeted'", tenant).Scan(&retargeted))
	if retargeted != 1 {
		t.Fatalf("merge must record binding retarget in history, got %d", retargeted)
	}
}
