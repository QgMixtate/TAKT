//go:build integration

package app_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/itsm"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/health"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// W3-01, W3-09: сотрудник входит на портал учёткой каталога (мок OpenLDAP по LDAPS), видит только каталог/свои
// обращения; реестр, склад и очередь операторов закрыты на уровне API; внутренний комментарий не виден; неверный
// пароль, пустой пароль, неизвестный и отключённый логин — общий отказ; локальный вход для пользователя каталога закрыт.
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
	// отключённый в каталоге сотрудник не входит
	ldapAdmin(t, ld, "ldapmodify", fmt.Sprintf("dn: uid=orlova,%s\nchangetype: modify\nreplace: userPassword\nuserPassword: changed-elsewhere\n", base))
	portalLogin(newBrowser(t, server), "orlova", "Portal-orlova-1", 401)
	var audits int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND action='portal.login'", tenant).Scan(&audits)
	if audits != 2 {
		t.Fatal("portal logins must be audited", audits)
	}
}
