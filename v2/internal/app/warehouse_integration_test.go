//go:build integration

package app_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/warehouse"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/health"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Волна 2 (C43.01–C43.02, C42.02, C44 частично; AC W2-01…03, W2-04, W2-07, W2-08 — decisions/C41-w2-scope-and-model.md):
// приход, выдача/возврат, две одновременные выдачи одного экземпляра, выдача сверх остатка, ремонт, установка/снятие
// на актив, списание экземпляра-актива с выводом актива из учёта, журнал только дописывается, остатки = журнал, права.
func TestW2WarehouseIssueReturnConcurrencyWriteOff(t *testing.T) {
	f := registrySetup(t)
	for _, u := range []string{"operator", "viewer"} {
		if err := f.users.Provision(f.ctx, false, tenant, "", u, password, u); err != nil {
			t.Fatal(err)
		}
	}
	person := identifier.New()
	if _, err := f.pool.Exec(f.ctx, "INSERT INTO responsibility.subjects(tenant_id,subject_id,kind,name,contact) VALUES($1,$2,'person','Иванов И. И.','ivanov@example.test')", tenant, person); err != nil {
		t.Fatal(err)
	}
	team := "00000000-0000-4000-8000-000000000002"
	asset := *f.ingest(t, f.observation("1")).AssetID
	auth, err := access.NewHTTP(f.users, "https://ui.example", false)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := app.NewHTTP(auth, health.Handler(func(context.Context) error { return nil }), f.registry)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	type session struct {
		b    browser
		csrf string
	}
	login := func(user string) session { b := newBrowser(t, server); return session{b, b.login(t, user).CSRFToken} }
	admin, operator, viewer := login("admin"), login("operator"), login("viewer")
	schemaRaw, err := os.ReadFile("../../contracts/w2-warehouse.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	doc, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(schemaRaw)))
	if err = compiler.AddResource("urn:surveyscan:w2:warehouse:1:0", doc); err != nil {
		t.Fatal(err)
	}
	contract := map[string]string{"/api/v1/warehouse/locations": "Location", "/api/v1/warehouse/items": "Item", "/api/v1/warehouse/movements": "Movement"}
	listContract := map[string]string{"/api/v1/warehouse/locations": "LocationList", "/api/v1/warehouse/items": "ItemList", "/api/v1/warehouse/units": "UnitList", "/api/v1/warehouse/stock": "StockList", "/api/v1/warehouse/movements": "MovementList", "/api/v1/warehouse/verify": "StockVerification"}
	call := func(s session, method, path, body string, want int) []byte {
		t.Helper()
		code, raw, _ := s.b.request(t, method, path, body, s.csrf, "https://ui.example", nil)
		if code != want {
			t.Fatalf("%s %s: %d (want %d) %s", method, path, code, want, raw)
		}
		base, _, _ := strings.Cut(path, "?")
		def := ""
		switch {
		case code >= 300:
		case method == "POST":
			def = contract[base]
		case strings.HasPrefix(base, "/api/v1/warehouse/movements/"):
			def = "Movement"
		default:
			def = listContract[base]
		}
		if def != "" {
			schema, err := compiler.Compile("urn:surveyscan:w2:warehouse:1:0#/$defs/" + def)
			if err != nil {
				t.Fatal(err)
			}
			inst, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
			if err = schema.Validate(inst); err != nil {
				t.Fatalf("%s violates w2-warehouse: %v %s", def, err, raw)
			}
		}
		return raw
	}
	var loc, bin, repair warehouse.Location
	_ = json.Unmarshal(call(admin, "POST", "/api/v1/warehouse/locations", fmt.Sprintf(`{"site_id":%q,"kind":"warehouse","name":"Склад 1"}`, siteID), 201), &loc)
	_ = json.Unmarshal(call(admin, "POST", "/api/v1/warehouse/locations", fmt.Sprintf(`{"site_id":%q,"kind":"bin","parent_id":%q,"name":"Ячейка А"}`, siteID, loc.ID), 201), &bin)
	_ = json.Unmarshal(call(admin, "POST", "/api/v1/warehouse/locations", fmt.Sprintf(`{"site_id":%q,"kind":"repair","name":"Сервис-центр"}`, siteID), 201), &repair)
	call(operator, "POST", "/api/v1/warehouse/locations", fmt.Sprintf(`{"site_id":%q,"kind":"warehouse","name":"Склад 2"}`, siteID), 403) // каталог и места — администратор
	call(admin, "POST", "/api/v1/warehouse/locations", fmt.Sprintf(`{"site_id":%q,"kind":"warehouse","name":"склад 1"}`, siteID), 409)
	var laptop, ssd, cable warehouse.Item
	_ = json.Unmarshal(call(admin, "POST", "/api/v1/warehouse/items", `{"name":"Ноутбук Lenovo T14","kind":"serial","category":"ПК"}`, 201), &laptop)
	_ = json.Unmarshal(call(admin, "POST", "/api/v1/warehouse/items", `{"name":"SSD 1 ТБ","kind":"serial"}`, 201), &ssd)
	_ = json.Unmarshal(call(admin, "POST", "/api/v1/warehouse/items", `{"name":"Кабель UTP","kind":"quantity","unit":"м"}`, 201), &cable)
	call(admin, "POST", "/api/v1/warehouse/items", `{"name":"Серийный в метрах","kind":"serial","unit":"м"}`, 422)

	move := func(s session, want int, op string) warehouse.Movement {
		t.Helper()
		var m warehouse.Movement
		_ = json.Unmarshal(call(s, "POST", "/api/v1/warehouse/movements", op, want), &m)
		return m
	}
	// W2-01: приход экземпляров (ноутбук — это актив реестра) и количества
	in := move(operator, 201, fmt.Sprintf(`{"kind":"receive","basis":"Накладная 15","to_location":%q,"lines":[{"item_id":%q,"serial":"PF-1","inventory_no":"ИНВ-001","asset_uid":%q},{"item_id":%q,"serial":"SSD-9"},{"item_id":%q,"quantity":100}]}`, bin.ID, laptop.ID, asset, ssd.ID, cable.ID))
	if len(in.Lines) != 3 || in.ActNo == "" || !strings.HasPrefix(in.ActNo, fmt.Sprint(in.At.Year())+"-") {
		t.Fatalf("receive: %+v", in)
	}
	pc, disk := *in.Lines[0].UnitID, *in.Lines[1].UnitID
	move(operator, 409, fmt.Sprintf(`{"kind":"receive","basis":"Повтор","to_location":%q,"lines":[{"item_id":%q,"serial":"pf-1"}]}`, bin.ID, laptop.ID)) // серийный номер уникален
	move(viewer, 403, fmt.Sprintf(`{"kind":"receive","basis":"x","to_location":%q,"lines":[{"item_id":%q,"quantity":1}]}`, bin.ID, cable.ID))

	// W2-02: две одновременные выдачи одного экземпляра — ровно одна успешна
	codes := make([]int, 2)
	var wg sync.WaitGroup
	for i, to := range []string{person, team} {
		wg.Add(1)
		go func(i int, to string) {
			defer wg.Done()
			codes[i], _, _ = operator.b.request(t, "POST", "/api/v1/warehouse/movements", fmt.Sprintf(`{"kind":"issue","basis":"Заявка %d","from_location":%q,"to_holder":%q,"lines":[{"unit_id":%q}]}`, i, bin.ID, to, pc), operator.csrf, "https://ui.example", nil)
		}(i, to)
	}
	wg.Wait()
	if !((codes[0] == 201 && codes[1] == 409) || (codes[0] == 409 && codes[1] == 201)) {
		t.Fatalf("concurrent issue: %v", codes)
	}
	var issues int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM warehouse.movement_lines l JOIN warehouse.movements m USING(tenant_id,movement_id) WHERE m.kind='issue' AND l.unit_id=$1", pc).Scan(&issues)
	if issues != 1 {
		t.Fatal("one issue in the journal, got", issues)
	}
	var units struct{ Items []warehouse.Unit }
	_ = json.Unmarshal(call(viewer, "GET", "/api/v1/warehouse/units?asset="+asset, "", 200), &units)
	if len(units.Items) != 1 || units.Items[0].State != "issued" || units.Items[0].Holder == nil {
		t.Fatalf("issued unit: %+v", units.Items)
	}
	holder := *units.Items[0].Holder
	move(operator, 201, fmt.Sprintf(`{"kind":"return","basis":"Увольнение","from_holder":%q,"to_location":%q,"lines":[{"unit_id":%q}]}`, holder, loc.ID, pc))
	move(operator, 409, fmt.Sprintf(`{"kind":"return","basis":"Повтор","from_holder":%q,"to_location":%q,"lines":[{"unit_id":%q}]}`, holder, loc.ID, pc))

	// W2-03: количество — не больше остатка, одновременные выдачи не уводят в минус
	move(operator, 409, fmt.Sprintf(`{"kind":"issue","basis":"Много","from_location":%q,"to_holder":%q,"lines":[{"item_id":%q,"quantity":101}]}`, bin.ID, person, cable.ID))
	ok := make([]int, 6)
	for i := range ok {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ok[i], _, _ = operator.b.request(t, "POST", "/api/v1/warehouse/movements", fmt.Sprintf(`{"kind":"issue","basis":"Монтаж","from_location":%q,"to_holder":%q,"lines":[{"item_id":%q,"quantity":30}]}`, bin.ID, person, cable.ID), operator.csrf, "https://ui.example", nil)
		}(i)
	}
	wg.Wait()
	granted := 0
	for _, c := range ok {
		if c == 201 {
			granted++
		} else if c != 409 {
			t.Fatal("unexpected code", c)
		}
	}
	var stock struct{ Items []warehouse.StockRow }
	_ = json.Unmarshal(call(viewer, "GET", "/api/v1/warehouse/stock?location="+bin.ID, "", 200), &stock)
	left := 0.0
	for _, s := range stock.Items {
		left += s.Quantity
	}
	if granted != 3 || left != 10 {
		t.Fatalf("100 m, 6×30 m requested: granted %d, left %v", granted, left)
	}

	// W2-04: ремонт и замена комплектующего на активе (asset_uid не меняется)
	move(operator, 201, fmt.Sprintf(`{"kind":"repair_out","basis":"Не включается","from_location":%q,"to_location":%q,"lines":[{"unit_id":%q}]}`, loc.ID, repair.ID, pc))
	move(operator, 201, fmt.Sprintf(`{"kind":"repair_in","basis":"Отремонтирован","from_location":%q,"to_location":%q,"lines":[{"unit_id":%q}]}`, repair.ID, loc.ID, pc))
	move(operator, 201, fmt.Sprintf(`{"kind":"install","basis":"Замена диска","from_location":%q,"asset_uid":%q,"lines":[{"unit_id":%q}]}`, bin.ID, asset, disk))
	move(operator, 409, fmt.Sprintf(`{"kind":"install","basis":"Повтор","from_location":%q,"asset_uid":%q,"lines":[{"unit_id":%q}]}`, bin.ID, asset, disk))
	move(operator, 422, fmt.Sprintf(`{"kind":"install","basis":"Без актива","from_location":%q,"lines":[{"unit_id":%q}]}`, bin.ID, disk))
	var history struct{ Items []warehouse.Movement }
	_ = json.Unmarshal(call(viewer, "GET", "/api/v1/warehouse/movements?asset="+asset, "", 200), &history)
	if len(history.Items) < 5 {
		t.Fatalf("asset history must include its unit movements and installs: %d", len(history.Items))
	}

	// W2-07: списание экземпляра-актива — только администратор; актив выведен из учёта с тем же основанием
	move(operator, 403, fmt.Sprintf(`{"kind":"write_off","basis":"Акт ТС-1","from_location":%q,"lines":[{"unit_id":%q}]}`, loc.ID, pc))
	wo := move(admin, 201, fmt.Sprintf(`{"kind":"write_off","basis":"Акт технического состояния ТС-1","from_location":%q,"lines":[{"unit_id":%q}]}`, loc.ID, pc))
	var reason string
	if err = f.pool.QueryRow(f.ctx, "SELECT retired_reason FROM assets.assets WHERE tenant_id=$1 AND asset_uid=$2", tenant, asset).Scan(&reason); err != nil || !strings.Contains(reason, wo.ActNo) || !strings.Contains(reason, "ТС-1") {
		t.Fatal("asset must be retired with the write-off act", reason, err)
	}
	move(operator, 409, fmt.Sprintf(`{"kind":"issue","basis":"После списания","from_location":%q,"to_holder":%q,"lines":[{"unit_id":%q}]}`, loc.ID, person, pc))

	// журнал только дописывается; остатки = журнал; акт читается
	if _, err = f.pool.Exec(f.ctx, "UPDATE warehouse.movements SET basis='x' WHERE tenant_id=$1", tenant); err == nil {
		t.Fatal("movements must be append-only")
	}
	if raw := call(admin, "GET", "/api/v1/warehouse/verify", "", 200); !strings.Contains(string(raw), `"discrepancies":[]`) {
		t.Fatalf("stock must equal the journal: %s", raw)
	}
	call(operator, "GET", "/api/v1/warehouse/verify", "", 403)
	var act warehouse.Movement
	_ = json.Unmarshal(call(viewer, "GET", "/api/v1/warehouse/movements/"+wo.ID, "", 200), &act)
	if act.ActNo != wo.ActNo || len(act.Lines) != 1 || act.Lines[0].Serial == nil || *act.Lines[0].Serial != "PF-1" {
		t.Fatalf("act: %+v", act)
	}
	var audits int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND action LIKE 'warehouse.%'", tenant).Scan(&audits)
	if audits < 12 {
		t.Fatal("every warehouse operation must be audited", audits)
	}
}
