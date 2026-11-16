//go:build integration

package app_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/itsm"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/messaging"
)

// Волна 3 (C50; AC W3-07, W3-08): SLA — сроки в рабочих часах, пауза «ждём заявителя», предупреждение и нарушение
// (фоновый проход), остановка при решении; события обращений доставляются webhook, повтор — с тем же event_id.
func TestW3SLAAndTicketWebhooks(t *testing.T) {
	env := c31Setup(t)
	f, call := env.f, env.call
	const urn = "urn:surveyscan:c31:integrations:1:0"
	var mu sync.Mutex
	var calls []hookCall
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		mu.Lock()
		calls = append(calls, hookCall{req.URL.Path, req.Header.Clone(), body})
		mu.Unlock()
		w.WriteHeader(204)
	}))
	defer receiver.Close()
	secretFile := filepath.Join(t.TempDir(), "webhook.key")
	_ = os.WriteFile(secretFile, []byte(strings.Repeat("k", 48)), 0o600)
	sender, err := app.NewWebhookSender(secretFile)
	if err != nil {
		t.Fatal(err)
	}
	sender.Client.Transport = receiver.Client().Transport
	f.registry.Webhooks = sender
	types := `["ticket.created.v1","ticket.state_changed.v1","ticket.assigned.v1","ticket.sla_warning.v1","ticket.sla_breached.v1"]`
	raw := call(env.admin, "POST", "/api/v1/webhooks", `{"url":"`+receiver.URL+`/itsm","event_types":`+types+`}`, 201)
	env.valid(urn, "WebhookCreated", raw)
	var created app.WebhookCreated
	_ = json.Unmarshal(raw, &created)
	sub := created.Subscription

	// W3-07: настройки SLA — по умолчанию; администратор задаёт круглосуточный календарь UTC и короткие сроки
	raw = call(env.op, "GET", "/api/v1/itsm/sla", "", 200)
	validW3(t, "SLASettings", raw)
	var set itsm.SLASettings
	_ = json.Unmarshal(raw, &set)
	if set.Revision != "0" || set.Hours.Timezone != "Europe/Moscow" || len(set.Policies) != 8 {
		t.Fatalf("defaults: %+v", set)
	}
	set.Hours = itsm.BusinessHours{Timezone: "UTC", Days: []int{1, 2, 3, 4, 5, 6, 7}, StartMinute: 0, EndMinute: 1440, WarnPercent: 80}
	for i := range set.Policies {
		if set.Policies[i].Kind == "incident" && set.Policies[i].Priority == 1 {
			set.Policies[i].Response, set.Policies[i].Resolution = 10, 60
		}
	}
	body, _ := json.Marshal(set)
	call(env.op, "PUT", "/api/v1/itsm/sla", string(body), 403)
	bad := strings.Replace(string(body), `"UTC"`, `"Nowhere/City"`, 1)
	call(env.admin, "PUT", "/api/v1/itsm/sla", bad, 422)
	raw = call(env.admin, "PUT", "/api/v1/itsm/sla", string(body), 200)
	validW3(t, "SLASettings", raw)
	call(env.admin, "PUT", "/api/v1/itsm/sla", string(body), 412) // ревизия устарела

	ticket := func(raw []byte) itsm.Detail {
		t.Helper()
		validW3(t, "TicketDetail", raw)
		var d itsm.Detail
		_ = json.Unmarshal(raw, &d)
		return d
	}
	timer := func(d itsm.Detail, metric string) itsm.Timer {
		t.Helper()
		for _, x := range d.SLA {
			if x.Metric == metric {
				return x
			}
		}
		t.Fatalf("no %s timer: %+v", metric, d.SLA)
		return itsm.Timer{}
	}
	// сдвиг времени таймеров: «прошло n минут» (тест не ждёт реальных минут)
	age := func(id string, minutes int) {
		t.Helper()
		if _, err := f.pool.Exec(f.ctx, "UPDATE itsm.sla_timers SET started_at=started_at-make_interval(mins=>$2),paused_since=paused_since-make_interval(mins=>$2) WHERE ticket_id=$1", id, minutes); err != nil {
			t.Fatal(err)
		}
	}
	inc := ticket(call(env.op, "POST", "/api/v1/itsm/tickets", `{"kind":"incident","title":"Не работает 1С","impact":1,"urgency":1}`, 201))
	if r := timer(inc, "response"); inc.Priority != 1 || r.Target != 10 || r.Status != "running" || r.DueAt == nil || timer(inc, "resolution").Target != 60 {
		t.Fatalf("timers: %+v", inc.SLA)
	}
	if prb := ticket(call(env.op, "POST", "/api/v1/itsm/tickets", `{"kind":"problem","title":"x","impact":3,"urgency":3}`, 201)); len(prb.SLA) != 0 {
		t.Fatal("problems have no SLA", prb.SLA)
	}
	// 9 минут без реакции → предупреждение (80 %); 11 → нарушение реакции; проход фоновой роли отмечает и пишет журнал
	age(inc.ID, 9)
	if n, err := f.registry.SLAPass(f.ctx); err != nil || n != 1 {
		t.Fatal("warning pass", n, err)
	}
	inc = ticket(call(env.op, "GET", "/api/v1/itsm/tickets/"+inc.ID, "", 200))
	if r := timer(inc, "response"); r.Status != "warning" || r.WarnedAt == nil {
		t.Fatalf("warning: %+v", r)
	}
	age(inc.ID, 2)
	if n, err := f.registry.SLAPass(f.ctx); err != nil || n != 1 {
		t.Fatal("breach pass", n, err)
	}
	if n, _ := f.registry.SLAPass(f.ctx); n != 0 {
		t.Fatal("marks are made once", n)
	}
	inc = ticket(call(env.op, "GET", "/api/v1/itsm/tickets/"+inc.ID, "", 200))
	if r := timer(inc, "response"); r.Status != "breached" || r.BreachedAt == nil {
		t.Fatalf("breached: %+v", r)
	}
	// очередь показывает SLA
	raw = call(env.op, "GET", "/api/v1/itsm/tickets?state=open", "", 200)
	validW3(t, "TicketList", raw)
	if !strings.Contains(string(raw), `"status":"breached"`) {
		t.Fatalf("queue must show SLA: %s", raw)
	}
	// реакция (в работу) останавливает таймер реакции — «просрочено»; решение идёт дальше
	inc = ticket(call(env.op, "POST", "/api/v1/itsm/tickets/"+inc.ID+"/transition", fmt.Sprintf(`{"revision":%q,"to":"in_progress"}`, inc.Revision), 200))
	if r := timer(inc, "response"); r.Status != "missed" {
		t.Fatalf("response stopped late: %+v", r)
	}
	// пауза «ждём заявителя»: время паузы не считается
	inc = ticket(call(env.op, "POST", "/api/v1/itsm/tickets/"+inc.ID+"/transition", fmt.Sprintf(`{"revision":%q,"to":"waiting_customer"}`, inc.Revision), 200))
	before := timer(inc, "resolution")
	if before.Status != "paused" {
		t.Fatalf("paused: %+v", before)
	}
	if _, err := f.pool.Exec(f.ctx, "UPDATE itsm.sla_timers SET paused_since=paused_since-interval '30 minutes' WHERE ticket_id=$1 AND metric='resolution'", inc.ID); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.registry.SLAPass(f.ctx); n != 0 {
		t.Fatal("paused timers are not marked", n)
	}
	inc = ticket(call(env.op, "POST", "/api/v1/itsm/tickets/"+inc.ID+"/transition", fmt.Sprintf(`{"revision":%q,"to":"in_progress"}`, inc.Revision), 200))
	if after := timer(inc, "resolution"); after.Status != "running" || after.Elapsed > before.Elapsed+1 {
		t.Fatalf("pause must not count: before %+v after %+v", before, after)
	}
	// решение в срок — «выполнено»
	inc = ticket(call(env.op, "POST", "/api/v1/itsm/tickets/"+inc.ID+"/transition", fmt.Sprintf(`{"revision":%q,"to":"resolved","text":"Перезапущен сервер 1С"}`, inc.Revision), 200))
	if r := timer(inc, "resolution"); r.Status != "met" || r.DueAt != nil {
		t.Fatalf("resolution met: %+v", r)
	}
	sla := 0
	for _, e := range inc.Events {
		if e.Kind == "sla" {
			sla++
		}
	}
	if sla != 2 {
		t.Fatalf("journal must hold warning and breach: %d", sla)
	}

	// W3-08: события обращения доставлены по подписке; повторная доставка — тот же event_id (идемпотентный ключ)
	for range 3 {
		if _, err := f.registry.DeliverWebhooks(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	got := append([]hookCall{}, calls...)
	mu.Unlock()
	seen := map[string]int{}
	ids := map[string]bool{}
	var first messaging.WebhookPayload
	for i, c := range got {
		var p messaging.WebhookPayload
		if err := json.Unmarshal(c.body, &p); err != nil {
			t.Fatal(err)
		}
		env.valid(urn, "WebhookPayload", c.body)
		if p.EventID != c.headers.Get("X-SurveyScan-Event-Id") || p.Aggregate.Type != "ticket" {
			t.Fatalf("payload: %s", c.body)
		}
		if p.Data["ticket_id"] == inc.ID {
			seen[p.EventType]++
		}
		if ids[p.EventID] {
			t.Fatal("each event is delivered once while the receiver answers 2xx")
		}
		ids[p.EventID] = true
		if strings.Contains(string(c.body), "1С") || strings.Contains(string(c.body), "Перезапущен") {
			t.Fatal("ticket texts must not leave the center", string(c.body))
		}
		if i == 0 {
			first = p
		}
	}
	if seen["ticket.created.v1"] != 1 || seen["ticket.sla_warning.v1"] != 1 || seen["ticket.sla_breached.v1"] != 1 || seen["ticket.state_changed.v1"] != 4 {
		t.Fatalf("ticket events: %+v", seen)
	}
	call(env.admin, "POST", "/api/v1/webhooks/"+sub.ID+"/deliveries/"+first.EventID+"/retry", "", 409) // доставленное не повторяется
	if _, err := f.pool.Exec(f.ctx, "UPDATE messaging.webhook_deliveries SET state='pending',next_attempt_at=now(),delivered_at=NULL WHERE event_id=$1", first.EventID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.registry.DeliverWebhooks(f.ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	last := calls[len(calls)-1]
	mu.Unlock()
	if last.headers.Get("X-SurveyScan-Event-Id") != first.EventID {
		t.Fatal("redelivery must carry the same event id for receiver-side deduplication")
	}
}
