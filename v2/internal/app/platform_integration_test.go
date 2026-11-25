//go:build integration

package app_test

import (
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/cmdb"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// C57.01: снимок платформы — объекты и связи записываются; ВМ сопоставляется с активом по BIOS UUID в форме с
// переставленными байтами (VMware); повтор снимка ничего не меняет; после 3 полных снимков без ВМ — «удалена».
func TestC57PlatformSnapshotMatchRepeatAndRemoval(t *testing.T) {
	f := registrySetup(t)
	f.ingest(t, f.observation("1")) // актив с machine_uuid 00000000-0000-4000-8000-000000000090
	var asset string
	if e := f.pool.QueryRow(f.ctx, "SELECT asset_uid::text FROM assets.assets WHERE tenant_id=$1 LIMIT 1", tenant).Scan(&asset); e != nil {
		t.Fatal(e)
	}
	swapped := "00000000-0000-0040-8000-000000000090"
	serial := "VMware-42 1a 2b"
	snap := func(complete bool, withVM bool) cmdb.PlatformSnapshot {
		s := cmdb.PlatformSnapshot{Major: 1, SnapshotID: identifier.New(), Tenant: tenant, Source: sourceID, Generation: generationID, Platform: "vsphere",
			Instance: "vc01.example", InstanceName: "vCenter", CollectedAt: time.Now().UTC().Truncate(time.Microsecond), Complete: complete, Errors: []string{},
			Objects: []cmdb.PlatformObject{
				{Ref: "domain-c7", Kind: "cluster", Name: "Prod", MACs: []string{}, Attrs: map[string]any{"ha": true, "drs": true}},
				{Ref: "host-10", Kind: "host", Name: "esx01", Serial: &serial, MACs: []string{}, Attrs: map[string]any{"version": "8.0.2", "cpus": 32.0}},
			},
			Relations: []cmdb.PlatformRelation{{From: "host-10", Type: "member_of", To: "domain-c7"}}}
		if withVM {
			s.Objects = append(s.Objects, cmdb.PlatformObject{Ref: "vm-42", Kind: "vm", Name: "host-one", BiosUUID: &swapped, MACs: []string{"aa:bb:cc:dd:ee:ff"}, Attrs: map[string]any{"vcpu": 4.0, "power": "poweredOn"}})
			s.Relations = append(s.Relations, cmdb.PlatformRelation{From: "vm-42", Type: "runs_on", To: "host-10"})
		}
		return s
	}
	save := func(s cmdb.PlatformSnapshot) cmdb.PlatformSnapshotResult {
		t.Helper()
		tx, e := f.pool.Begin(f.ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(f.ctx)
		out, e := f.registry.CMDB.SavePlatformSnapshot(f.ctx, tx, s)
		if e != nil {
			t.Fatal(e)
		}
		if e = tx.Commit(f.ctx); e != nil {
			t.Fatal(e)
		}
		return out
	}
	first := snap(true, true)
	out := save(first)
	if out.Duplicate || out.Objects != 3 || out.Matched != 1 || out.Removed != 0 {
		t.Fatalf("first snapshot %+v", out)
	}
	if again := save(first); !again.Duplicate {
		t.Fatalf("repeat must be a no-op: %+v", again)
	}
	tx, _ := f.pool.Begin(f.ctx)
	items, e := f.registry.CMDB.AssetPlatform(f.ctx, tx, tenant, asset)
	tx.Rollback(f.ctx)
	if e != nil || len(items) != 1 || items[0].Object.Kind != "vm" || len(items[0].Links) != 1 || items[0].Links[0].Object.Name != "esx01" || items[0].Links[0].Type != "runs_on" {
		t.Fatalf("asset platform path %+v %v", items, e)
	}
	// ВМ пропала из платформы: два полных снимка — ещё на месте, третий — удалена
	for i, want := range []int{0, 0, 1} {
		time.Sleep(2 * time.Millisecond)
		if got := save(snap(true, false)); got.Removed != want {
			t.Fatalf("snapshot %d removed=%d want %d", i+1, got.Removed, want)
		}
	}
	var removed *time.Time
	var rels int
	_ = f.pool.QueryRow(f.ctx, "SELECT removed_at FROM cmdb.platform_objects WHERE ref='vm-42'").Scan(&removed)
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM cmdb.platform_relations WHERE from_ref='vm-42'").Scan(&rels)
	if removed == nil || rels != 0 {
		t.Fatalf("vm must be removed with its relations: removed=%v rels=%d", removed, rels)
	}
	tx, _ = f.pool.Begin(f.ctx)
	list, e := f.registry.CMDB.PlatformInstances(f.ctx, tx, tenant)
	tx.Rollback(f.ctx)
	if e != nil || len(list) != 1 || list[0].Objects["host"] != 1 || list[0].Objects["cluster"] != 1 || list[0].Removed != 1 || list[0].LastCompleteAt == nil {
		t.Fatalf("instances %+v %v", list, e)
	}
	// неполный снимок не считает пропуски; ВМ вернулась — снова на месте
	if got := save(snap(false, true)); got.Removed != 0 || got.Matched != 1 {
		t.Fatalf("partial snapshot %+v", got)
	}
	_ = f.pool.QueryRow(f.ctx, "SELECT removed_at FROM cmdb.platform_objects WHERE ref='vm-42'").Scan(&removed)
	if removed != nil {
		t.Fatal("returned vm must be restored")
	}
	// компьютер AD: сопоставляется по имени (FQDN → короткое), только если актив с таким именем единственный
	fqdn := "host-one.corp.example"
	ad := cmdb.PlatformSnapshot{Major: 1, SnapshotID: identifier.New(), Tenant: tenant, Source: tenant, Generation: tenant, Platform: "ad", Instance: "ldaps://dc/DC=corp",
		InstanceName: "DC=corp", CollectedAt: time.Now().UTC(), Complete: true, Errors: []string{}, Relations: []cmdb.PlatformRelation{},
		Objects: []cmdb.PlatformObject{{Ref: "ad:1", Kind: "computer", Name: "HOST-ONE", Hostname: &fqdn, MACs: []string{}, Attrs: map[string]any{"os": "Windows Server 2022", "disabled": false}},
			{Ref: "ad:2", Kind: "computer", Name: "GHOST", MACs: []string{}, Attrs: map[string]any{}}}}
	if got := save(ad); got.Matched != 1 || got.Objects != 2 {
		t.Fatalf("ad computers %+v", got)
	}
}
