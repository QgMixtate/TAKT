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

// W3-01, W3-09: сотрудник входит на портал учёткой каталога (мок OpenLDAP по LDAPS), видит только каталог/свои
// обращения; реестр, склад и очередь операторов закрыты на уровне API; внутренний комментарий не виден; неверный
// пароль, пустой пароль, неизвестный и отключённый логин — общий отказ; локальный вход для пользователя каталога закрыт.
func validW3(t *testing.T, def string, raw []byte) {
	t.Helper()
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
	schema, err := compiler.Compile("urn:surveyscan:w3:itsm:1:0#/$defs/" + def)
	if err != nil {
		t.Fatal(err)
	}
	inst, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
	if err = schema.Validate(inst); err != nil {
		t.Fatalf("%s violates w3-itsm: %v %s", def, err, raw)
	}
}

func TestW3PortalDirectoryLogin(t *testing.T) {
	ld := ldapEnv(t)
	f := registrySetup(t)
	base := "ou=p" + strings.ReplaceAll(identifier.New()[:8], "-", "") + "," + ld["BASE_DN"]
	seed := "dn: " + base + "\nobjectClass: organizationalUnit\n\n"
	for _, p := range [][2]string{{"kuznetsov", "Сергей Кузнецов"}, {"orlova", "Анна Орлова"}} {
		seed += fmt.Sprintf("dn: uid=%s,%s\nobjectClass: inetOrgPerson\nuid: %s\ncn: %s\nsn: %s\ndisplayName: %s\nmail: %s@example.test\nuserPassword: Portal-%s-1\n\n", p[0], base, p[0], p[1], p[1], p[1], p[0], p[0])
	}
	ldapAdmin(t, ld, "ldapadd", seed)
	t.Cleanup(func() { ldapAdmin(t, ld, "ldapdelete", base+"\n", "-r") })
	d, err := app.NewDirectorySync(app.DirectorySyncConfig{TenantID: tenant, URL: ld["URL"], BaseDN: base, BindDN: ld["BIND_DN"], PasswordFile: ld["PASSWORD_FILE"], CAFile: ld["CA_FILE"],
		UserFilter: "(objectClass=inetOrgPerson)", GroupFilter: "(objectClass=groupOfNames)", GUIDAttribute: "entryUUID", LoginAttribute: "uid", ChangedAttribute: "modifyTimestamp"})
	if err != nil {
		t.Fatal(err)
	}
	f.registry.Directory = d
	if _, err = f.registry.SyncDirectory(f.ctx, true); err != nil {
		t.Fatal(err)
	}
	if err = f.users.Provision(f.ctx, false, tenant, "", "op1", password, "operator"); err != nil {
		t.Fatal(err)
	}
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

	portalLogin := func(b browser, login, pw string, want int) string {
		t.Helper()
		code, raw, _ := b.request(t, "POST", "/api/v1/auth/directory-sessions", fmt.Sprintf(`{"login":%q,"password":%q}`, login, pw), "", "https://ui.example", nil)
		if code != want {
			t.Fatalf("portal login %s: %d (want %d) %s", login, code, want, raw)
		}
		var s access.Session
		_ = json.Unmarshal(raw, &s)
		if want == 201 && (len(s.Roles) != 1 || s.Roles[0] != "requester") {
			t.Fatalf("portal session must be requester: %s", raw)
		}
		return s.CSRFToken
	}
	emp := newBrowser(t, server)
	for _, bad := range [][2]string{{"kuznetsov", "wrong"}, {"kuznetsov", ""}, {"nobody", "Portal-nobody-1"}, {"AWM\\nobody", "x"}} {
		portalLogin(newBrowser(t, server), bad[0], bad[1], 401)
	}
	csrf := portalLogin(emp, `AWM\kuznetsov`, "Portal-kuznetsov-1", 201) // DOMAIN\login → login
	// локальный вход для пользователя каталога закрыт (у него нет локального пароля)
	if code, _, _ := newBrowser(t, server).request(t, "POST", "/api/v1/auth/sessions", `{"username":"ad.kuznetsov","password":"Portal-kuznetsov-1"}`, "", "https://ui.example", nil); code != 401 {
		t.Fatal("directory user must not log in with a local password", code)
	}
	call := func(b browser, csrf, method, path, body string, want int) []byte {
		t.Helper()
		code, raw, _ := b.request(t, method, path, body, csrf, "https://ui.example", nil)
		if code != want {
			t.Fatalf("%s %s: %d (want %d) %s", method, path, code, want, raw)
		}
		return raw
	}
	// W3-01: реестр, склад, очередь операторов — закрыты для заявителя
	for _, path := range []string{"/api/v1/assets", "/api/v1/warehouse/units", "/api/v1/itsm/tickets", "/api/v1/sources"} {
		call(emp, csrf, "GET", path, "", 403)
	}
	var mine itsm.Detail
	_ = json.Unmarshal(call(emp, csrf, "POST", "/api/v1/portal/tickets", `{"title":"Не работает VPN","description":"с утра","urgency":1}`, 201), &mine)
	if mine.Requester == nil || mine.Priority != 3 || mine.State != "new" {
		t.Fatalf("portal ticket: %+v", mine)
	}
	// оператор видит обращение в очереди, пишет внутренний и публичный комментарии, решает
	op := newBrowser(t, server)
	opCSRF := op.login(t, "op1").CSRFToken
	call(op, opCSRF, "POST", "/api/v1/itsm/tickets/"+mine.ID+"/comments", `{"text":"проверить сертификат VPN-шлюза","internal":true}`, 201)
	call(op, opCSRF, "POST", "/api/v1/itsm/tickets/"+mine.ID+"/comments", `{"text":"Переподключитесь, пожалуйста"}`, 201)
	var opView itsm.Detail
	_ = json.Unmarshal(call(op, opCSRF, "GET", "/api/v1/itsm/tickets/"+mine.ID, "", 200), &opView)
	// «ждём заявителя» → ответ сотрудника на портале возвращает обращение в работу (стенд №15)
	_ = json.Unmarshal(call(op, opCSRF, "POST", "/api/v1/itsm/tickets/"+mine.ID+"/transition", fmt.Sprintf(`{"revision":%q,"to":"in_progress"}`, opView.Revision), 200), &opView)
	_ = json.Unmarshal(call(op, opCSRF, "POST", "/api/v1/itsm/tickets/"+mine.ID+"/transition", fmt.Sprintf(`{"revision":%q,"to":"waiting_customer"}`, opView.Revision), 200), &opView)
	call(emp, csrf, "POST", "/api/v1/portal/tickets/"+mine.ID+"/comments", `{"text":"Переподключился, не помогло"}`, 201)
	_ = json.Unmarshal(call(op, opCSRF, "GET", "/api/v1/itsm/tickets/"+mine.ID, "", 200), &opView)
	if opView.State != "in_progress" {
		t.Fatalf("requester reply must return the ticket to work: %s", opView.State)
	}
	_ = json.Unmarshal(call(op, opCSRF, "POST", "/api/v1/itsm/tickets/"+mine.ID+"/transition", fmt.Sprintf(`{"revision":%q,"to":"resolved","text":"Обновлён сертификат"}`, opView.Revision), 200), &opView)
	// W3-09: заявитель не видит внутренний комментарий, видит публичный
	raw := call(emp, csrf, "GET", "/api/v1/portal/tickets/"+mine.ID, "", 200)
	if strings.Contains(string(raw), "сертификат VPN-шлюза") || !strings.Contains(string(raw), "Переподключитесь") {
		t.Fatalf("requester view must hide internal comments: %s", raw)
	}
	var view itsm.Detail
	_ = json.Unmarshal(raw, &view)
	if view.State != "resolved" || len(view.Allowed) != 2 {
		t.Fatalf("requester confirms resolution: %+v", view)
	}
	// «не решено» → повторное открытие; второй сотрудник не видит чужое обращение
	_ = json.Unmarshal(call(emp, csrf, "POST", "/api/v1/portal/tickets/"+mine.ID+"/confirm", fmt.Sprintf(`{"revision":%q,"solved":false,"text":"Всё ещё не работает"}`, view.Revision), 200), &view)
	if view.State != "in_progress" || view.Reopens != 1 {
		t.Fatalf("not solved must reopen: %+v", view)
	}
	other := newBrowser(t, server)
	otherCSRF := portalLogin(other, "orlova", "Portal-orlova-1", 201)
	call(other, otherCSRF, "GET", "/api/v1/portal/tickets/"+mine.ID, "", 404)
	call(other, otherCSRF, "POST", "/api/v1/portal/tickets/"+mine.ID+"/comments", `{"text":"чужое"}`, 404)
	if raw := call(other, otherCSRF, "GET", "/api/v1/portal/tickets", "", 200); strings.Contains(string(raw), mine.ID) {
		t.Fatal("another employee must not list foreign tickets")
	}
	// оператор не пользуется порталом (только заявитель)
	call(op, opCSRF, "GET", "/api/v1/portal/tickets", "", 403)
	// W3-05: заявка «Выдать ноутбук» — каталог (администратор) → портал → согласование руководителем с портала →
	// исполнение выдачей со склада (акт со ссылкой на заявку) → подтверждение; повтор исполнения не выдаёт второй раз.
	if err = f.users.Provision(f.ctx, false, tenant, "", "adm", password, "admin"); err != nil {
		t.Fatal(err)
	}
	adm := newBrowser(t, server)
	admCSRF := adm.login(t, "adm").CSRFToken
	var orlova string
	if err = f.pool.QueryRow(f.ctx, `SELECT s.subject_id::text FROM responsibility.subjects s JOIN access.users u ON u.tenant_id=s.tenant_id AND u.user_id=s.user_id
WHERE s.tenant_id=$1 AND u.username='ad.orlova'`, tenant).Scan(&orlova); err != nil {
		t.Fatal(err)
	}
	var loc, laptop struct {
		ID string `json:"location_id"`
		It string `json:"item_id"`
	}
	_ = json.Unmarshal(call(adm, admCSRF, "POST", "/api/v1/warehouse/locations", fmt.Sprintf(`{"site_id":%q,"kind":"warehouse","name":"Склад ИТ"}`, siteID), 201), &loc)
	_ = json.Unmarshal(call(adm, admCSRF, "POST", "/api/v1/warehouse/items", `{"name":"Ноутбук 14","kind":"serial"}`, 201), &laptop)
	var in struct {
		Lines []struct {
			Unit string `json:"unit_id"`
		} `json:"lines"`
	}
	_ = json.Unmarshal(call(adm, admCSRF, "POST", "/api/v1/warehouse/movements", fmt.Sprintf(`{"kind":"receive","basis":"Накладная 7","to_location":%q,"lines":[{"item_id":%q,"serial":"NB-1"},{"item_id":%q,"serial":"NB-2"}]}`, loc.ID, laptop.It, laptop.It), 201), &in)
	form := `[{"key":"model","label":"Диагональ","type":"select","required":true,"options":["14","16"]},{"key":"reason","label":"Обоснование","type":"textarea","required":false,"options":[]}]`
	call(op, opCSRF, "POST", "/api/v1/itsm/catalog", `{"name":"x","form":[]}`, 403) // каталог — администратор
	call(adm, admCSRF, "POST", "/api/v1/itsm/catalog", `{"name":"Плохая форма","form":[{"key":"Bad Key","label":"x","type":"text","required":false,"options":[]}]}`, 422)
	var svc itsm.CatalogItem
	raw = call(adm, admCSRF, "POST", "/api/v1/itsm/catalog", fmt.Sprintf(`{"name":"Выдать ноутбук","description":"Рабочий ноутбук","form":%s,"approver_id":%q,"warehouse_item_id":%q}`, form, orlova, laptop.It), 201)
	validW3(t, "CatalogItem", raw)
	_ = json.Unmarshal(raw, &svc)
	raw = call(emp, csrf, "GET", "/api/v1/portal/catalog", "", 200)
	validW3(t, "CatalogList", raw)
	if !strings.Contains(string(raw), "Выдать ноутбук") || strings.Contains(string(raw), orlova) {
		t.Fatalf("portal catalog: %s", raw)
	}
	call(emp, csrf, "POST", "/api/v1/portal/requests", fmt.Sprintf(`{"catalog_item_id":%q,"form_values":{"reason":"x"}}`, svc.ID), 422)         // обязательное поле
	call(emp, csrf, "POST", "/api/v1/portal/requests", fmt.Sprintf(`{"catalog_item_id":%q,"form_values":{"model":"17"}}`, svc.ID), 422)         // нет такого варианта
	call(emp, csrf, "POST", "/api/v1/portal/requests", fmt.Sprintf(`{"catalog_item_id":%q,"form_values":{"model":"14","x":"1"}}`, svc.ID), 422) // лишнее поле
	var req itsm.Detail
	raw = call(emp, csrf, "POST", "/api/v1/portal/requests", fmt.Sprintf(`{"catalog_item_id":%q,"form_values":{"model":"14","reason":"новый сотрудник"}}`, svc.ID), 201)
	validW3(t, "TicketDetail", raw)
	_ = json.Unmarshal(raw, &req)
	if !strings.HasPrefix(req.Number, "REQ-") || req.State != "pending_approval" || req.Request == nil || req.Request.Values["model"] != "14" || !strings.Contains(req.Description, "Диагональ: 14") {
		t.Fatalf("request: %s", raw)
	}
	fulfillBody := func(rev, unit string) string {
		return fmt.Sprintf(`{"revision":%q,"from_location":%q,"unit_id":%q}`, rev, loc.ID, unit)
	}
	call(op, opCSRF, "POST", "/api/v1/itsm/tickets/"+req.ID+"/fulfill", fulfillBody(req.Revision, in.Lines[0].Unit), 409)                  // не согласована
	call(emp, csrf, "POST", "/api/v1/portal/tickets/"+req.ID+"/approve", fmt.Sprintf(`{"revision":%q,"approve":true}`, req.Revision), 403) // сам себе не согласует
	raw = call(other, otherCSRF, "GET", "/api/v1/portal/approvals", "", 200)
	validW3(t, "TicketList", raw)
	if !strings.Contains(string(raw), req.ID) {
		t.Fatalf("approver must see the pending request: %s", raw)
	}
	call(other, otherCSRF, "POST", "/api/v1/portal/tickets/"+req.ID+"/approve", fmt.Sprintf(`{"revision":%q,"approve":true,"comment":"Согласовано"}`, req.Revision), 200)
	call(other, otherCSRF, "POST", "/api/v1/portal/tickets/"+req.ID+"/approve", fmt.Sprintf(`{"revision":%q,"approve":true}`, req.Revision), 409) // решение одно
	_ = json.Unmarshal(call(op, opCSRF, "GET", "/api/v1/itsm/tickets/"+req.ID, "", 200), &req)
	if req.State != "in_fulfillment" || req.Request.Approval == nil || req.Request.Approval.Decision != "approved" {
		t.Fatalf("approved: %+v", req)
	}
	// одновременное исполнение двумя операторами разными экземплярами — выдача одна
	codes := make([]int, 2)
	var wg sync.WaitGroup
	for i, unit := range []string{in.Lines[0].Unit, in.Lines[1].Unit} {
		wg.Add(1)
		go func(i int, unit string) {
			defer wg.Done()
			codes[i], _, _ = op.request(t, "POST", "/api/v1/itsm/tickets/"+req.ID+"/fulfill", fulfillBody(req.Revision, unit), opCSRF, "https://ui.example", nil)
		}(i, unit)
	}
	wg.Wait()
	if !(codes[0] == 200 && codes[1] != 200 || codes[1] == 200 && codes[0] != 200) {
		t.Fatalf("concurrent fulfill: %v", codes)
	}
	raw = call(op, opCSRF, "GET", "/api/v1/itsm/tickets/"+req.ID, "", 200)
	validW3(t, "TicketDetail", raw)
	_ = json.Unmarshal(raw, &req)
	act := false
	for _, l := range req.Links {
		act = act || l.Kind == "movement" && strings.HasPrefix(l.Label, "акт ")
	}
	if req.State != "fulfilled" || !act || req.Resolution == nil {
		t.Fatalf("fulfilled with act link: %s", raw)
	}
	call(op, opCSRF, "POST", "/api/v1/itsm/tickets/"+req.ID+"/fulfill", fulfillBody(req.Revision, in.Lines[1].Unit), 409) // повтор
	var issues, held int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM warehouse.movements WHERE tenant_id=$1 AND kind='issue' AND basis LIKE 'Заявка '||$2||'%'", tenant, req.Number).Scan(&issues)
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM warehouse.units WHERE tenant_id=$1 AND holder_id=$2", tenant, *req.Requester).Scan(&held)
	if issues != 1 || held != 1 {
		t.Fatalf("one issue to the requester: issues=%d held=%d", issues, held)
	}
	var mineReq itsm.Detail
	_ = json.Unmarshal(call(emp, csrf, "GET", "/api/v1/portal/tickets/"+req.ID, "", 200), &mineReq)
	if mineReq.State != "fulfilled" || len(mineReq.Allowed) != 2 {
		t.Fatalf("requester confirms fulfillment: %+v", mineReq)
	}
	_ = json.Unmarshal(call(emp, csrf, "POST", "/api/v1/portal/tickets/"+req.ID+"/confirm", fmt.Sprintf(`{"revision":%q,"solved":true}`, mineReq.Revision), 200), &mineReq)
	if mineReq.State != "closed" {
		t.Fatalf("closed: %+v", mineReq)
	}
	// отклонение — только с причиной; отклонённая заявка закрыта
	var rej itsm.Detail
	_ = json.Unmarshal(call(emp, csrf, "POST", "/api/v1/portal/requests", fmt.Sprintf(`{"catalog_item_id":%q,"form_values":{"model":"16"}}`, svc.ID), 201), &rej)
	call(other, otherCSRF, "POST", "/api/v1/portal/tickets/"+rej.ID+"/approve", fmt.Sprintf(`{"revision":%q,"approve":false}`, rej.Revision), 422)
	_ = json.Unmarshal(call(other, otherCSRF, "POST", "/api/v1/portal/tickets/"+rej.ID+"/approve", fmt.Sprintf(`{"revision":%q,"approve":false,"comment":"Уже выдан"}`, rej.Revision), 200), &rej)
	if rej.State != "rejected" || rej.ClosedAt == nil {
		t.Fatalf("rejected: %+v", rej)
	}
	// услуга без согласования сразу уходит в исполнение
	var simple itsm.CatalogItem
	_ = json.Unmarshal(call(adm, admCSRF, "POST", "/api/v1/itsm/catalog", `{"name":"Сброс пароля","form":[]}`, 201), &simple)
	_ = json.Unmarshal(call(emp, csrf, "POST", "/api/v1/portal/requests", fmt.Sprintf(`{"catalog_item_id":%q,"form_values":{}}`, simple.ID), 201), &rej)
	if rej.State != "in_fulfillment" {
		t.Fatalf("no approval: %+v", rej)
	}
	call(op, opCSRF, "POST", "/api/v1/itsm/tickets", `{"kind":"request","title":"x","impact":3,"urgency":3}`, 422) // заявка — только по услуге каталога
	// отключённый в каталоге сотрудник не входит
	ldapAdmin(t, ld, "ldapmodify", fmt.Sprintf("dn: uid=orlova,%s\nchangetype: modify\nreplace: userPassword\nuserPassword: changed-elsewhere\n", base))
	portalLogin(newBrowser(t, server), "orlova", "Portal-orlova-1", 401)
	var audits int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND action='portal.login'", tenant).Scan(&audits)
	if audits != 2 {
		t.Fatal("portal logins must be audited", audits)
	}
}
