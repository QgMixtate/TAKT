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

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/itsm"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/health"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// Волна 3 (C47.01–C47.02; AC W3-02…W3-04): инцидент от регистрации до закрытия с повторным открытием, два оператора
// одновременно берут инцидент (назначение одно), проблема по инцидентам с обходным решением, права и журнал.
func TestW3IncidentsAndProblems(t *testing.T) {
	f := registrySetup(t)
	subjects := map[string]string{}
	for _, u := range []string{"op1", "op2", "viewer"} {
		role := "operator"
		if u == "viewer" {
			role = "viewer"
		}
		if err := f.users.Provision(f.ctx, false, tenant, "", u, password, role); err != nil {
			t.Fatal(err)
		}
		subject := identifier.New()
		if _, err := f.pool.Exec(f.ctx, `INSERT INTO responsibility.subjects(tenant_id,subject_id,kind,name,contact,user_id)
SELECT $1,$2,'person',$3,$3||'@example.test',user_id FROM access.users WHERE tenant_id=$1 AND username=$3`, tenant, subject, u); err != nil {
			t.Fatal(err)
		}
		subjects[u] = subject
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
	schemaRaw, err := os.ReadFile("../../contracts/w3-itsm.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	doc, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(schemaRaw)))
	if err = compiler.AddResource("urn:surveyscan:w3:itsm:1:0", doc); err != nil {
		t.Fatal(err)
	}
	valid := func(def string, raw []byte) {
		t.Helper()
		schema, err := compiler.Compile("urn:surveyscan:w3:itsm:1:0#/$defs/" + def)
		if err != nil {
			t.Fatal(err)
		}
		inst, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
		if err = schema.Validate(inst); err != nil {
			t.Fatalf("%s violates w3-itsm: %v %s", def, err, raw)
		}
	}
	type session struct {
		b    browser
		csrf string
	}
	login := func(user string) session { b := newBrowser(t, server); return session{b, b.login(t, user).CSRFToken} }
	op1, op2, viewer := login("op1"), login("op2"), login("viewer")
	call := func(s session, method, path, body string, want int) itsm.Detail {
		t.Helper()
		code, raw, _ := s.b.request(t, method, path, body, s.csrf, "https://ui.example", nil)
		if code != want {
			t.Fatalf("%s %s: %d (want %d) %s", method, path, code, want, raw)
		}
		var d itsm.Detail
		if code < 300 && method != "GET" || strings.Contains(path, "/tickets/") && code == 200 {
			valid("TicketDetail", raw)
			_ = json.Unmarshal(raw, &d)
		}
		return d
	}
	// W3-02: регистрация инцидента с привязкой к активу; приоритет из влияния и срочности
	inc := call(op1, "POST", "/api/v1/itsm/tickets", fmt.Sprintf(`{"kind":"incident","title":"Не печатает принтер","description":"Бухгалтерия","impact":2,"urgency":1,"requester_id":%q,"asset_uid":%q}`, subjects["viewer"], asset), 201)
	if !strings.HasPrefix(inc.Number, "INC-") || inc.Priority != 2 || inc.State != "new" || len(inc.Links) != 1 || inc.Links[0].Kind != "asset" {
		t.Fatalf("incident: %+v", inc)
	}
	call(viewer, "POST", "/api/v1/itsm/tickets", `{"kind":"incident","title":"x","impact":3,"urgency":3}`, 403)
	call(op1, "POST", "/api/v1/itsm/tickets", `{"kind":"request","title":"x","impact":3,"urgency":3}`, 422) // заявки — C48

	// W3-03: два оператора одновременно «берут себе» — назначение одно, второй получает конфликт ревизии
	codes := make([]int, 2)
	var wg sync.WaitGroup
	for i, s := range []session{op1, op2} {
		wg.Add(1)
		go func(i int, s session) {
			defer wg.Done()
			codes[i], _, _ = s.b.request(t, "POST", "/api/v1/itsm/tickets/"+inc.ID+"/assign", `{"revision":"`+inc.Revision+`","me":true}`, s.csrf, "https://ui.example", nil)
		}(i, s)
	}
	wg.Wait()
	// второй получает 412 REVISION_MISMATCH (общий код конфликта ревизии API): обращение уже изменилось
	if !((codes[0] == 200 && codes[1] == 412) || (codes[0] == 412 && codes[1] == 200)) {
		t.Fatalf("concurrent take: %v", codes)
	}
	cur := call(op1, "GET", "/api/v1/itsm/tickets/"+inc.ID, "", 200)
	if cur.State != "assigned" || cur.Assignee == nil {
		t.Fatalf("assigned once: %+v", cur)
	}
	cur = call(op1, "POST", "/api/v1/itsm/tickets/"+inc.ID+"/assign", fmt.Sprintf(`{"revision":%q,"team_id":%q,"reason":"эскалация на 2-ю линию"}`, cur.Revision, team), 200)
	cur = call(op1, "POST", "/api/v1/itsm/tickets/"+inc.ID+"/transition", fmt.Sprintf(`{"revision":%q,"to":"in_progress"}`, cur.Revision), 200)
	call(op1, "POST", "/api/v1/itsm/tickets/"+inc.ID+"/transition", fmt.Sprintf(`{"revision":%q,"to":"closed"}`, cur.Revision), 409)    // нельзя закрыть нерешённый
	call(op1, "POST", "/api/v1/itsm/tickets/"+inc.ID+"/transition", fmt.Sprintf(`{"revision":%q,"to":"resolved"}`, cur.Revision), 422) // без решения
	call(op1, "POST", "/api/v1/itsm/tickets/"+inc.ID+"/comments", `{"text":"Проверить драйвер","internal":true}`, 201)
	cur = call(op1, "POST", "/api/v1/itsm/tickets/"+inc.ID+"/transition", fmt.Sprintf(`{"revision":%q,"to":"resolved","text":"Переустановлен драйвер"}`, cur.Revision), 200)
	cur = call(op1, "POST", "/api/v1/itsm/tickets/"+inc.ID+"/transition", fmt.Sprintf(`{"revision":%q,"to":"in_progress","text":"Снова не печатает"}`, cur.Revision), 200)
	if cur.Reopens != 1 || cur.ResolvedAt != nil {
		t.Fatalf("reopen: %+v", cur)
	}

	// W3-04: проблема по инциденту, обходное решение видно в инциденте
	prb := call(op2, "POST", "/api/v1/itsm/tickets", `{"kind":"problem","title":"Сбой драйвера печати","impact":2,"urgency":2}`, 201)
	call(op2, "POST", "/api/v1/itsm/tickets/"+prb.ID+"/links", fmt.Sprintf(`{"target_kind":"ticket","target_id":%q}`, inc.ID), 201)
	prb = call(op2, "GET", "/api/v1/itsm/tickets/"+prb.ID, "", 200)
	prb = call(op2, "POST", "/api/v1/itsm/tickets/"+prb.ID+"/transition", fmt.Sprintf(`{"revision":%q,"to":"investigating"}`, prb.Revision), 200)
	call(op2, "POST", "/api/v1/itsm/tickets/"+prb.ID+"/transition", fmt.Sprintf(`{"revision":%q,"to":"known_error","text":"Печать через PDF"}`, prb.Revision), 200)
	cur = call(op1, "GET", "/api/v1/itsm/tickets/"+inc.ID, "", 200)
	if len(cur.Workarounds) != 1 || !strings.Contains(cur.Workarounds[0], "Печать через PDF") {
		t.Fatalf("workaround must be visible on the incident: %+v", cur.Workarounds)
	}
	linked := false
	for _, l := range cur.Links {
		linked = linked || l.Kind == "ticket" && l.Target == prb.ID
	}
	if !linked {
		t.Fatalf("incident must show the problem link: %+v", cur.Links)
	}
	// журнал: создание, назначения, переходы, внутренний комментарий; аудит каждого действия
	kinds := map[string]int{}
	internal := 0
	for _, e := range cur.Events {
		kinds[e.Kind]++
		if !e.Public {
			internal++
		}
	}
	if kinds["created"] != 1 || kinds["assigned"] != 2 || kinds["state"] != 3 || internal != 1 {
		t.Fatalf("ticket journal: %+v internal=%d", kinds, internal)
	}
	if _, err = f.pool.Exec(f.ctx, "UPDATE itsm.ticket_events SET text='x' WHERE tenant_id=$1", tenant); err == nil {
		t.Fatal("ticket journal must be append-only")
	}
	code, raw, _ := op1.b.request(t, "GET", "/api/v1/itsm/tickets?kind=incident&state=open", "", op1.csrf, "https://ui.example", nil)
	if code != 200 || !strings.Contains(string(raw), inc.Number) {
		t.Fatalf("queue: %d %s", code, raw)
	}
	valid("TicketList", raw)
	var audits int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND action LIKE 'itsm.%'", tenant).Scan(&audits)
	if audits < 9 {
		t.Fatal("ticket actions must be audited", audits)
	}
}
