//go:build integration

package app_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// Стенд №18 (раздел 3): смена hostname того же узла — тот же актив, прежнее имя закрыто (valid_to), в истории
// HOSTNAME_CHANGED; повтор с тем же именем — без новой записи истории.
func TestHostnameChangeClosesOldIdentifier(t *testing.T) {
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
	mu := contracts.Candidate{Kind: "machine_uuid", Namespace: "linux-machine-id", Value: "4c4c4544-0000-1000-8000-" + identifier.New()[24:]}
	send := func(seq, name string) string {
		o := testObservation12(t, f, seq)
		o.Origin = contracts.Origin{SourceID: source, SourceKind: "portable", GenerationID: generation}
		o.Record = contracts.SourceRecord{Namespace: "host", LocalID: "host:rename"}
		o.Clock = "estimated"
		o.Candidates = []contracts.Candidate{mu, {Kind: "hostname", Namespace: "hostname.raw", Value: name}}
		raw, _ := json.Marshal(o)
		report, err := f.registry.ImportPortable(f.ctx, machine, tenant, source, portablePackage(t, key, source, raw))
		if err != nil || len(report.Records) != 1 || report.Records[0].Disposition != "applied" {
			t.Fatal(err, report)
		}
		return report.Records[0].AssetID
	}
	a := send("1", "calc-dep")
	if b := send("2", "calc-dep-renamed"); b != a {
		t.Fatal("renamed host must stay the same asset", a, b)
	}
	if c := send("3", "calc-dep-renamed"); c != a {
		t.Fatal("same name must stay the same asset", c)
	}
	var open, closed, history int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FILTER (WHERE valid_to IS NULL),count(*) FILTER (WHERE valid_to IS NOT NULL AND normalized_value='calc-dep') FROM assets.asset_identifiers WHERE tenant_id=$1 AND asset_uid=$2 AND kind='hostname'`, tenant, a).Scan(&open, &closed); err != nil || open != 1 || closed != 1 {
		t.Fatal("old hostname must be closed, new one open", open, closed, err)
	}
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM assets.asset_changes WHERE tenant_id=$1 AND asset_uid=$2 AND reason_code='HOSTNAME_CHANGED'", tenant, a).Scan(&history); err != nil || history != 1 {
		t.Fatal("rename must be recorded once in asset history", history, err)
	}
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	names, err := f.registry.Assets.Hostnames(f.ctx, tx, tenant, a)
	if err != nil || len(names) != 2 || names[0].Value != "calc-dep-renamed" || names[0].ValidTo != nil || names[1].ValidTo == nil {
		t.Fatal("card hostname history", names, err)
	}
	// №57: в истории «было → стало», карточка отдаёт историю без проекций описи
	hist, err := f.registry.Assets.AssetHistory(f.ctx, tx, tenant, a)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range hist {
		if h.ReasonCode == "INVENTORY_PROJECTED" {
			t.Fatal("inventory projections must not be listed in card history")
		}
		if h.ReasonCode == "HOSTNAME_CHANGED" {
			found = string(h.Details) != "" && strings.Contains(string(h.Details), `"from": ["calc-dep"]`) && strings.Contains(string(h.Details), `"to": ["calc-dep-renamed"]`)
		}
	}
	if !found {
		t.Fatalf("rename details missing: %+v", hist)
	}
}
