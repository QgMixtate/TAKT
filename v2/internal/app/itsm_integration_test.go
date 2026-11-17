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
	"time"

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
	// стенд №15: «Взять себе» после передачи команде не снимает команду
	cur = call(op2, "POST", "/api/v1/itsm/tickets/"+inc.ID+"/assign", fmt.Sprintf(`{"revision":%q,"me":true}`, cur.Revision), 200)
	if cur.Team == nil || *cur.Team != team || cur.Assignee == nil || *cur.Assignee != subjects["op2"] {
		t.Fatalf("take must keep the team: %+v", cur.Ticket)
	}
	cur = call(op1, "POST", "/api/v1/itsm/tickets/"+inc.ID+"/transition", fmt.Sprintf(`{"revision":%q,"to":"in_progress"}`, cur.Revision), 200)
	call(op1, "POST", "/api/v1/itsm/tickets/"+inc.ID+"/transition", fmt.Sprintf(`{"revision":%q,"to":"closed"}`, cur.Revision), 409)   // нельзя закрыть нерешённый
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
	if kinds["created"] != 1 || kinds["assigned"] != 3 || kinds["state"] != 3 || internal != 1 {
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

// Волна 3 (C49; AC W3-06): изменение — окно, согласование администратором, планирование, выполнение и откат;
// пересечение окон на одном активе без подтверждения отклоняется, с подтверждением — отмечается; календарь окон.
func TestW3Changes(t *testing.T) {
	f := registrySetup(t)
	for _, u := range [][2]string{{"op1", "operator"}, {"adm", "admin"}} {
		if err := f.users.Provision(f.ctx, false, tenant, "", u[0], password, u[1]); err != nil {
			t.Fatal(err)
		}
	}
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
	op, adm := login("op1"), login("adm")
	call := func(s session, method, path, body string, want int) itsm.Detail {
		t.Helper()
		code, raw, _ := s.b.request(t, method, path, body, s.csrf, "https://ui.example", nil)
		if code != want {
			t.Fatalf("%s %s: %d (want %d) %s", method, path, code, want, raw)
		}
		var d itsm.Detail
		if code < 300 && strings.Contains(path, "/tickets") {
			validW3(t, "TicketDetail", raw)
			_ = json.Unmarshal(raw, &d)
		}
		return d
	}
	base := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Hour)
	at := func(h int) string { return base.Add(time.Duration(h) * time.Hour).Format(time.RFC3339) }
	newChange := func(title string, from, to int) itsm.Detail {
		t.Helper()
		d := call(op, "POST", "/api/v1/itsm/tickets", fmt.Sprintf(`{"kind":"change","title":%q,"impact":2,"urgency":2,"asset_uid":%q}`, title, asset), 201)
		if !strings.HasPrefix(d.Number, "CHG-") || d.State != "draft" || d.Change == nil || d.Change.Window != nil {
			t.Fatalf("change: %+v", d)
		}
		return call(op, "POST", "/api/v1/itsm/tickets/"+d.ID+"/window", fmt.Sprintf(`{"revision":%q,"starts_at":%q,"ends_at":%q,"risk":"medium","plan":"Обновить прошивку","rollback_plan":"Вернуть прошлую прошивку"}`, d.Revision, at(from), at(to)), 200)
	}
	step := func(s session, d itsm.Detail, to, text string, want int) itsm.Detail {
		t.Helper()
		out := call(s, "POST", "/api/v1/itsm/tickets/"+d.ID+"/transition", fmt.Sprintf(`{"revision":%q,"to":%q,"text":%q}`, d.Revision, to, text), want)
		if want != 200 {
			return call(s, "GET", "/api/v1/itsm/tickets/"+d.ID, "", 200)
		}
		return out
	}
	approve := func(s session, d itsm.Detail, yes bool, comment string, want int) itsm.Detail {
		t.Helper()
		out := call(s, "POST", "/api/v1/itsm/tickets/"+d.ID+"/approve", fmt.Sprintf(`{"revision":%q,"approve":%t,"comment":%q}`, d.Revision, yes, comment), want)
		if want != 200 {
			return call(s, "GET", "/api/v1/itsm/tickets/"+d.ID, "", 200)
		}
		return out
	}

	// без окна — нельзя подать; неверное окно — 422
	draft := call(op, "POST", "/api/v1/itsm/tickets", `{"kind":"change","title":"Без окна","impact":3,"urgency":3}`, 201)
	step(op, draft, "submitted", "", 422)
	call(op, "POST", "/api/v1/itsm/tickets/"+draft.ID+"/window", fmt.Sprintf(`{"revision":%q,"starts_at":%q,"ends_at":%q,"risk":"medium","plan":"x","rollback_plan":"y"}`, draft.Revision, at(2), at(1)), 422)
	call(op, "POST", "/api/v1/itsm/tickets/"+draft.ID+"/window", fmt.Sprintf(`{"revision":%q,"starts_at":%q,"ends_at":%q,"risk":"extreme","plan":"x","rollback_plan":"y"}`, draft.Revision, at(1), at(2)), 422)

	// первое изменение: окно 10–12 → подача → согласование (только администратор) → план → выполнение → закрытие
	c1 := newChange("Прошивка коммутатора", 10, 12)
	c1 = step(op, c1, "submitted", "", 200)
	c1 = approve(op, c1, true, "", 403) // оператор не согласует изменения
	c1 = approve(adm, c1, true, "CAB: согласовано", 200)
	if c1.State != "approved" || c1.Change.Approval == nil || c1.Change.Approval.Decision != "approved" {
		t.Fatalf("approved: %+v", c1.Change)
	}
	c1 = step(op, c1, "scheduled", "", 200)

	// второе изменение на том же активе: окно 11–13 пересекается — без подтверждения отказ, с подтверждением — план
	c2 := newChange("Замена блока питания", 11, 13)
	c2 = step(op, c2, "submitted", "", 200)
	c2 = approve(adm, c2, true, "", 200)
	if len(c2.Change.Conflicts) != 1 || c2.Change.Conflicts[0].TicketID != c1.ID {
		t.Fatalf("conflict must be visible before scheduling: %+v", c2.Change.Conflicts)
	}
	code, raw, _ := op.b.request(t, "POST", "/api/v1/itsm/tickets/"+c2.ID+"/transition", fmt.Sprintf(`{"revision":%q,"to":"scheduled"}`, c2.Revision), op.csrf, "https://ui.example", nil)
	if code != 409 || !strings.Contains(string(raw), "WINDOW_CONFLICT") {
		t.Fatalf("overlapping windows need confirmation: %d %s", code, raw)
	}
	c2 = call(op, "POST", "/api/v1/itsm/tickets/"+c2.ID+"/transition", fmt.Sprintf(`{"revision":%q,"to":"scheduled","confirm_conflicts":true}`, c2.Revision), 200)
	if c2.State != "scheduled" || !c2.Change.Window.ConflictsConfirmed {
		t.Fatalf("confirmed conflict: %+v", c2.Change)
	}
	// третье — не пересекается (14–15): без конфликтов; отклонение — только с причиной
	c3 := newChange("Перезагрузка", 14, 15)
	if len(c3.Change.Conflicts) != 0 {
		t.Fatalf("no overlap expected: %+v", c3.Change.Conflicts)
	}
	c3 = step(op, c3, "submitted", "", 200)
	c3 = approve(adm, c3, false, "", 422)
	c3 = approve(adm, c3, false, "Нет окна у подрядчика", 200)
	if c3.State != "rejected" || c3.ClosedAt == nil {
		t.Fatalf("rejected: %+v", c3.Ticket)
	}

	// выполнение: успех с проверкой и откат с причиной — текст обязателен
	c1 = step(op, c1, "in_progress", "", 200)
	c1 = step(op, c1, "completed", "", 422)
	c1 = step(op, c1, "completed", "Прошивка 15.2 работает, порты подняты", 200)
	c1 = step(op, c1, "closed", "", 200)
	c2 = step(op, c2, "in_progress", "", 200)
	c2 = step(op, c2, "rolled_back", "Блок не подошёл, возвращён старый", 200)
	if c2.Resolution == nil || !strings.Contains(*c2.Resolution, "возвращён") {
		t.Fatalf("rollback reason: %+v", c2.Ticket)
	}
	// связанный инцидент
	inc := call(op, "POST", "/api/v1/itsm/tickets", `{"kind":"incident","title":"После замены пропала связь","impact":2,"urgency":1}`, 201)
	call(op, "POST", "/api/v1/itsm/tickets/"+c2.ID+"/links", fmt.Sprintf(`{"target_kind":"ticket","target_id":%q}`, inc.ID), 201)

	// календарь окон за период: все три (отклонённое не показывается)
	code, raw, _ = op.b.request(t, "GET", "/api/v1/itsm/changes/calendar?from="+at(0)+"&to="+at(24), "", op.csrf, "https://ui.example", nil)
	if code != 200 {
		t.Fatalf("calendar: %d %s", code, raw)
	}
	validW3(t, "CalendarList", raw)
	if !strings.Contains(string(raw), c1.Number) || !strings.Contains(string(raw), c2.Number) || strings.Contains(string(raw), c3.Number) {
		t.Fatalf("calendar content: %s", raw)
	}
	code, _, _ = op.b.request(t, "GET", "/api/v1/itsm/changes/calendar?from="+at(0)+"&to="+at(24*100), "", op.csrf, "https://ui.example", nil)
	if code != 422 {
		t.Fatal("calendar period is limited", code)
	}
	// журнал: окно, согласование, переходы
	c2 = call(op, "GET", "/api/v1/itsm/tickets/"+c2.ID, "", 200)
	kinds := map[string]int{}
	for _, e := range c2.Events {
		kinds[e.Kind]++
	}
	if kinds["window"] != 1 || kinds["approval"] != 1 || kinds["state"] < 4 {
		t.Fatalf("change journal: %+v", kinds)
	}
}
