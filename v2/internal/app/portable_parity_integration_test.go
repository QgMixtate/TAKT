//go:build integration

package app_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

// registryView — то, что видит пользователь в реестре, без полей, зависящих от способа доставки (id источника,
// наблюдения, времени приёма): число активов, имя/ОС карточки, факты 1.2 и состояние секций.
type registryView struct {
	Assets, Conflicts int
	Hostname, OS      string
	Facts, Sections   []string
}

func viewOf(t *testing.T, f *registryFixture, asset string) registryView {
	t.Helper()
	var v registryView
	if err := f.pool.QueryRow(f.ctx, "SELECT (SELECT count(*) FROM assets.assets WHERE tenant_id=$1),(SELECT count(*) FROM assets.reconciliation_conflicts WHERE tenant_id=$1)", tenant).Scan(&v.Assets, &v.Conflicts); err != nil {
		t.Fatal(err)
	}
	rows, err := f.pool.Query(f.ctx, "SELECT section_name||'|'||record_key||'|'||field_name||'|'||value::text FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=$2", tenant, asset)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var s string
		if err = rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		v.Facts = append(v.Facts, s)
	}
	rows.Close()
	rows, err = f.pool.Query(f.ctx, "SELECT section_name||'|'||last_status FROM inventory.record_section_state12 WHERE tenant_id=$1 AND asset_uid=$2", tenant, asset)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var s string
		if err = rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		v.Sections = append(v.Sections, s)
	}
	rows.Close()
	sort.Strings(v.Facts)
	sort.Strings(v.Sections)
	card := detail(t, f, asset)
	if card.Snapshot.Hostname != nil {
		v.Hostname = *card.Snapshot.Hostname
	}
	if card.Snapshot.OS != nil {
		v.OS = *card.Snapshot.OS
	}
	return v
}

// C23.04 (AC-05): один и тот же снимок хоста, доставленный по сети (courier → Stage/Process) и файлом (portable-пакет),
// даёт эквивалентный реестр; позднее наблюдение (пакет, собранный дни назад) сохраняется, а не отвергается.
// Каждая половина — на своей чистой базе: иначе вторая доставка просто перекрыла бы факты первой.
func TestC23OfflineParityWithOnline(t *testing.T) {
	var online, offline registryView
	collected := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	sectionsAt := func(o *contracts.Observation) {
		o.CollectedAt = collected
		for i := range o.Sections {
			o.Sections[i].CollectedAt = collected
		}
	}

	t.Run("online", func(t *testing.T) {
		u := uploadSetup(t)
		f := u.f
		protocol, err := f.registry.ConfigureInventoryProtocol12(true)
		if err != nil {
			t.Fatal(err)
		}
		u.service.Protocol = protocol
		o := testObservation12(t, f, "1")
		o.Origin = u.observation("1").Origin
		sectionsAt(&o)
		raw, err := wire.RecordJSON(contracts.Batch{Version: contracts.Version{Major: 1, Minor: 2}, TenantID: tenant, DeliveryID: identifier.New(), Records: []json.RawMessage{f.signed(t, o)}})
		if err != nil {
			t.Fatal(err)
		}
		transport, err := u.service.Stage(f.ctx, u.fingerprint, raw)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := u.service.Process(f.ctx, u.fingerprint, transport.DeliveryID)
		if err != nil {
			t.Fatal(err)
		}
		verified, _, err := protocol.VerifyCenterResult(receipt, raw, u.service.KeyID, u.key.Public().(ed25519.PublicKey))
		if err != nil || len(verified.Payload.Results) != 1 || verified.Payload.Results[0].AssetID == nil {
			t.Fatal("online delivery not applied", err)
		}
		online = viewOf(t, f, *verified.Payload.Results[0].AssetID)
	})

	t.Run("file", func(t *testing.T) {
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
		o.Clock = "estimated"
		sectionsAt(&o)
		payload, err := json.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		report, err := f.registry.ImportPortable(f.ctx, machine, tenant, source, portablePackage(t, key, source, payload))
		if err != nil || len(report.Records) != 1 || report.Records[0].AssetID == "" || report.Records[0].Disposition == "rejected" || report.Records[0].Disposition == "quarantined" {
			t.Fatalf("file delivery not applied: %+v %v", report, err)
		}
		asset := report.Records[0].AssetID
		offline = viewOf(t, f, asset)

		// позднее наблюдение: пакет, собранный три дня назад и привезённый сейчас, сохраняется (история), не создаёт
		// второй актив и не перекрывает более свежие факты
		late := testObservation12(t, f, "2")
		late.Origin, late.Clock = o.Origin, "estimated"
		old := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Microsecond)
		late.CollectedAt = old
		for i := range late.Sections {
			late.Sections[i].CollectedAt = old
		}
		lp, err := json.Marshal(late)
		if err != nil {
			t.Fatal(err)
		}
		lr, err := f.registry.ImportPortable(f.ctx, machine, tenant, source, portablePackage(t, key, source, lp))
		if err != nil || len(lr.Records) != 1 || lr.Records[0].Disposition == "rejected" || lr.Records[0].Disposition == "quarantined" {
			t.Fatalf("late observation must be kept: %+v %v", lr, err)
		}
		var stored time.Time
		if err = f.pool.QueryRow(f.ctx, "SELECT collected_at FROM inventory.observations WHERE tenant_id=$1 AND observation_id=$2", tenant, late.ID).Scan(&stored); err != nil || !stored.Equal(old) {
			t.Fatal("late observation must be stored with its own collection time", stored, err)
		}
		if after := viewOf(t, f, asset); !reflect.DeepEqual(after, offline) {
			t.Fatalf("late observation changed the current registry:\nbefore %+v\nafter  %+v", offline, after)
		}
	})

	if t.Failed() {
		return
	}
	if online.Assets != 1 || online.Conflicts != 0 || len(online.Facts) == 0 || len(online.Sections) != 12 {
		t.Fatalf("online baseline incomplete: %+v", online)
	}
	if !reflect.DeepEqual(online, offline) {
		t.Fatalf("online and file deliveries of one snapshot must give an equivalent registry:\nonline  %+v\noffline %+v", online, offline)
	}
}
