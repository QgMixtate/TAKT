package itsm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

type Store struct{}

// Процессы (C46.03): допустимые переходы по виду обращения. Переход в assigned — только назначением.
var transitions = map[string]map[string][]string{
	"incident": {
		"new":              {"in_progress", "resolved", "cancelled"},
		"assigned":         {"in_progress", "resolved", "cancelled"},
		"in_progress":      {"waiting_customer", "resolved", "cancelled"},
		"waiting_customer": {"in_progress", "resolved", "cancelled"},
		"resolved":         {"in_progress", "closed"}, // повторное открытие или закрытие
	},
	"problem": {
		"new":           {"investigating", "cancelled"},
		"investigating": {"known_error", "resolved", "cancelled"},
		"known_error":   {"resolved", "cancelled"},
		"resolved":      {"investigating", "closed"},
	},
	// заявка (C48): pending_approval → in_fulfillment | rejected — только решением согласующего (Approve)
	"request": {
		"pending_approval": {"cancelled"},
		"in_fulfillment":   {"fulfilled", "cancelled"},
		"fulfilled":        {"in_fulfillment", "closed"}, // «не выполнено» заявителем или закрытие
	},
}

var initial = map[string]string{"incident": "new", "problem": "new"}
var prefix = map[string]string{"incident": "INC", "request": "REQ", "change": "CHG", "problem": "PRB"}

// Priority — приоритет из влияния и срочности (1 — высокое): 2→P1, 3→P2, 4→P3, 5–6→P4.
func Priority(impact, urgency int) int {
	switch s := impact + urgency; {
	case s <= 2:
		return 1
	case s == 3:
		return 2
	case s == 4:
		return 3
	}
	return 4
}

type Ticket struct {
	ID          string     `json:"ticket_id"`
	Kind        string     `json:"kind"`
	Number      string     `json:"number"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Impact      int        `json:"impact"`
	Urgency     int        `json:"urgency"`
	Priority    int        `json:"priority"`
	State       string     `json:"state"`
	Requester   *string    `json:"requester_id"`
	Assignee    *string    `json:"assignee_id"`
	Team        *string    `json:"team_id"`
	Resolution  *string    `json:"resolution"`
	Workaround  *string    `json:"workaround"`
	Reopens     int        `json:"reopen_count"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	ResolvedAt  *time.Time `json:"resolved_at"`
	ClosedAt    *time.Time `json:"closed_at"`
	Revision    string     `json:"revision"`
}

type Link struct {
	Kind   string `json:"target_kind"`
	Target string `json:"target_id"`
	Label  string `json:"label"` // номер обращения / имя сервиса / имя актива / акт склада
}

type Event struct {
	ID     string          `json:"event_id"`
	Kind   string          `json:"kind"`
	Public bool            `json:"public"`
	Detail json.RawMessage `json:"detail"`
	Text   *string         `json:"text"`
	Actor  string          `json:"actor_ref"`
	At     time.Time       `json:"occurred_at"`
}

type Detail struct {
	Ticket
	Allowed []string `json:"allowed_transitions"`
	Links   []Link   `json:"links"`
	Events  []Event  `json:"events"`
	// Workarounds — обходные решения проблем, связанных с этим инцидентом (W3-04)
	Workarounds []string `json:"workarounds"`
	// Request — услуга, значения формы, согласование (только у заявок)
	Request *Request `json:"request"`
}

type Input struct {
	Kind        string `json:"kind"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Impact      int    `json:"impact"`
	Urgency     int    `json:"urgency"`
	Requester   string `json:"requester_id,omitempty"`
	Asset       string `json:"asset_uid,omitempty"`
	Service     string `json:"service_uid,omitempty"`
}

func clean(s string, min, max int) (string, bool) {
	s = strings.TrimSpace(s)
	n := utf8.RuneCountInString(s)
	return s, n >= min && n <= max && utf8.ValidString(s)
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func pgConflict(e error) error {
	var pg *pgconn.PgError
	if errors.As(e, &pg) && (pg.Code == "23505" || pg.Code == "23503" || pg.Code == "23514") {
		return domain.Conflict
	}
	return e
}

func activeSubject(ctx context.Context, tx pgx.Tx, tenant, id, kind string) error {
	var ok bool
	if e := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM responsibility.subjects WHERE tenant_id=$1 AND subject_id=$2 AND active AND ($3='' OR kind=$3))", tenant, id, kind).Scan(&ok); e != nil {
		return e
	}
	if !ok {
		return domain.Invalid
	}
	return nil
}

func event(ctx context.Context, tx pgx.Tx, tenant, ticket, actor, kind string, public bool, detail any, text *string) error {
	raw, _ := json.Marshal(detail)
	_, e := tx.Exec(ctx, "INSERT INTO itsm.ticket_events(tenant_id,event_id,ticket_id,kind,public,detail,text,actor_ref) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", tenant, identifier.New(), ticket, kind, public, raw, text, actor)
	return e
}

// Create регистрирует инцидент или проблему (заявка — CreateRequest по услуге каталога; изменения — C49).
func (s Store) Create(ctx context.Context, tx pgx.Tx, tenant, actor string, in Input) (Detail, error) {
	state, known := initial[in.Kind]
	if !known {
		return Detail{}, domain.Invalid
	}
	return s.create(ctx, tx, tenant, actor, in, state, nil, nil, nil)
}

func (s Store) create(ctx context.Context, tx pgx.Tx, tenant, actor string, in Input, state string, catalog *string, values []byte, team *string) (Detail, error) {
	title, ok1 := clean(in.Title, 1, 256)
	desc, ok2 := clean(in.Description, 0, 8000)
	if !ok1 || !ok2 || in.Impact < 1 || in.Impact > 3 || in.Urgency < 1 || in.Urgency > 3 {
		return Detail{}, domain.Invalid
	}
	if in.Requester != "" {
		if e := activeSubject(ctx, tx, tenant, in.Requester, ""); e != nil {
			return Detail{}, e
		}
	}
	id := identifier.New()
	var at time.Time
	if e := tx.QueryRow(ctx, "SELECT now()").Scan(&at); e != nil {
		return Detail{}, e
	}
	var no int
	if e := tx.QueryRow(ctx, `INSERT INTO itsm.ticket_counters(tenant_id,prefix,year,last) VALUES($1,$2,$3,1)
ON CONFLICT (tenant_id,prefix,year) DO UPDATE SET last=itsm.ticket_counters.last+1 RETURNING last`, tenant, prefix[in.Kind], at.Year()).Scan(&no); e != nil {
		return Detail{}, e
	}
	number := fmt.Sprintf("%s-%d-%06d", prefix[in.Kind], at.Year(), no)
	if _, e := tx.Exec(ctx, `INSERT INTO itsm.tickets(tenant_id,ticket_id,kind,number,title,description,impact,urgency,priority,state,requester_id,created_by,created_at,updated_at,catalog_item_id,form_values,team_id)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13,$14,$15,$16)`, tenant, id, in.Kind, number, title, desc, in.Impact, in.Urgency, Priority(in.Impact, in.Urgency), state, nullable(in.Requester), actor, at, catalog, values, team); e != nil {
		return Detail{}, pgConflict(e)
	}
	if e := event(ctx, tx, tenant, id, actor, "created", true, map[string]any{"state": state, "priority": Priority(in.Impact, in.Urgency)}, nil); e != nil {
		return Detail{}, e
	}
	for kind, target := range map[string]string{"asset": in.Asset, "service": in.Service} {
		if target != "" {
			if e := s.Link(ctx, tx, tenant, actor, id, kind, target); e != nil {
				return Detail{}, e
			}
		}
	}
	return s.Detail(ctx, tx, tenant, id, true)
}

func scanTicket(r pgx.Row, t *Ticket) error {
	return r.Scan(&t.ID, &t.Kind, &t.Number, &t.Title, &t.Description, &t.Impact, &t.Urgency, &t.Priority, &t.State, &t.Requester, &t.Assignee, &t.Team,
		&t.Resolution, &t.Workaround, &t.Reopens, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt, &t.ResolvedAt, &t.ClosedAt, &t.Revision)
}

// Detail — обращение со связями и журналом; internal=false скрывает внутренние комментарии (заявитель, W3-09).
func (Store) Detail(ctx context.Context, tx pgx.Tx, tenant, id string, internal bool) (Detail, error) {
	var d Detail
	if !identifier.Valid(id) {
		return d, domain.NotFound
	}
	e := scanTicket(tx.QueryRow(ctx, `SELECT t.ticket_id::text,t.kind,t.number,t.title,t.description,t.impact,t.urgency,t.priority,t.state,t.requester_id::text,t.assignee_id::text,t.team_id::text,
t.resolution,t.workaround,t.reopen_count,t.created_by,t.created_at,t.updated_at,t.resolved_at,t.closed_at,t.revision::text FROM itsm.tickets t WHERE t.tenant_id=$1 AND t.ticket_id=$2`, tenant, id), &d.Ticket)
	if errors.Is(e, pgx.ErrNoRows) {
		return d, domain.NotFound
	}
	if e != nil {
		return d, e
	}
	d.Allowed = append([]string{}, transitions[d.Kind][d.State]...)
	rows, e := tx.Query(ctx, `SELECT l.target_kind,l.target_id::text,COALESCE(CASE l.target_kind
 WHEN 'ticket' THEN (SELECT o.number||' '||o.title FROM itsm.tickets o WHERE o.tenant_id=l.tenant_id AND o.ticket_id=l.target_id)
 WHEN 'service' THEN (SELECT s.name FROM cmdb.services s WHERE s.tenant_id=l.tenant_id AND s.service_uid=l.target_id)
 WHEN 'movement' THEN (SELECT 'акт '||m.act_no FROM warehouse.movements m WHERE m.tenant_id=l.tenant_id AND m.movement_id=l.target_id)
 WHEN 'asset' THEN (SELECT b.display_name FROM assets.asset_business_fields b WHERE b.tenant_id=l.tenant_id AND b.asset_uid=l.target_id) END,'')
FROM itsm.ticket_links l WHERE l.tenant_id=$1 AND l.ticket_id=$2
UNION ALL
SELECT 'ticket',l.ticket_id::text,(SELECT o.number||' '||o.title FROM itsm.tickets o WHERE o.tenant_id=l.tenant_id AND o.ticket_id=l.ticket_id)
FROM itsm.ticket_links l WHERE l.tenant_id=$1 AND l.target_kind='ticket' AND l.target_id=$2 ORDER BY 1,3`, tenant, id)
	if e != nil {
		return d, e
	}
	if d.Links, e = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Link, error) {
		var l Link
		return l, r.Scan(&l.Kind, &l.Target, &l.Label)
	}); e != nil {
		return d, e
	}
	rows, e = tx.Query(ctx, `SELECT event_id::text,kind,public,detail,text,actor_ref,occurred_at FROM itsm.ticket_events
WHERE tenant_id=$1 AND ticket_id=$2 AND (public OR $3) ORDER BY occurred_at,event_id LIMIT 1000`, tenant, id, internal)
	if e != nil {
		return d, e
	}
	if d.Events, e = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Event, error) {
		var v Event
		return v, r.Scan(&v.ID, &v.Kind, &v.Public, &v.Detail, &v.Text, &v.Actor, &v.At)
	}); e != nil {
		return d, e
	}
	rows, e = tx.Query(ctx, `SELECT p.number||': '||p.workaround FROM itsm.tickets p WHERE p.tenant_id=$1 AND p.kind='problem' AND p.workaround IS NOT NULL
AND p.state NOT IN ('closed','cancelled') AND (EXISTS(SELECT 1 FROM itsm.ticket_links l WHERE l.tenant_id=p.tenant_id AND l.ticket_id=p.ticket_id AND l.target_kind='ticket' AND l.target_id=$2)
 OR EXISTS(SELECT 1 FROM itsm.ticket_links l WHERE l.tenant_id=p.tenant_id AND l.ticket_id=$2 AND l.target_kind='ticket' AND l.target_id=p.ticket_id)) ORDER BY p.number`, tenant, id)
	if e != nil {
		return d, e
	}
	d.Workarounds, e = pgx.CollectRows(rows, pgx.RowTo[string])
	if d.Workarounds == nil {
		d.Workarounds = []string{}
	}
	if e != nil || d.Kind != "request" {
		return d, e
	}
	r := &Request{}
	var values []byte
	if e = tx.QueryRow(ctx, `SELECT c.item_id::text,c.name,COALESCE(t.form_values,'{}'::jsonb),c.approver_id::text,c.warehouse_item_id::text FROM itsm.tickets t
JOIN itsm.catalog_items c ON c.tenant_id=t.tenant_id AND c.item_id=t.catalog_item_id WHERE t.tenant_id=$1 AND t.ticket_id=$2`, tenant, id).Scan(&r.CatalogItem, &r.CatalogName, &values, &r.Approver, &r.WarehouseItem); e != nil {
		return d, e
	}
	if e = json.Unmarshal(values, &r.Values); e != nil {
		return d, e
	}
	a := &Approval{}
	e = tx.QueryRow(ctx, "SELECT approver_id::text,decision,comment,decided_by,decided_at FROM itsm.approvals WHERE tenant_id=$1 AND ticket_id=$2", tenant, id).Scan(&a.Approver, &a.Decision, &a.Comment, &a.DecidedBy, &a.DecidedAt)
	switch {
	case errors.Is(e, pgx.ErrNoRows):
		e = nil
	case e == nil:
		r.Approval = a
	}
	d.Request = r
	return d, e
}

// Filter — очередь: вид, состояние (open — все незакрытые), исполнитель, команда, заявитель, поиск по номеру/теме.
type Filter struct{ Kind, State, Assignee, Team, Requester, Query string }

func (Store) List(ctx context.Context, tx pgx.Tx, tenant string, f Filter, limit int) ([]Ticket, error) {
	rows, e := tx.Query(ctx, `SELECT t.ticket_id::text,t.kind,t.number,t.title,t.description,t.impact,t.urgency,t.priority,t.state,t.requester_id::text,t.assignee_id::text,t.team_id::text,
t.resolution,t.workaround,t.reopen_count,t.created_by,t.created_at,t.updated_at,t.resolved_at,t.closed_at,t.revision::text FROM itsm.tickets t WHERE t.tenant_id=$1
AND ($2='' OR t.kind=$2) AND ($3='' OR ($3='open' AND t.state NOT IN ('closed','cancelled','resolved','fulfilled','rejected')) OR t.state=$3)
AND ($4='' OR t.assignee_id::text=$4) AND ($5='' OR t.team_id::text=$5) AND ($6='' OR t.requester_id::text=$6)
AND ($7='' OR lower(t.number)=lower($7) OR lower(t.title) LIKE '%'||lower($7)||'%')
ORDER BY t.priority, t.created_at LIMIT $8`, tenant, f.Kind, f.State, f.Assignee, f.Team, f.Requester, f.Query, limit)
	if e != nil {
		return nil, e
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Ticket, error) {
		var t Ticket
		return t, scanTicket(r, &t)
	})
}

// Transition — смена состояния по таблице процесса с проверкой ревизии (конкурентное изменение — Revision).
// resolved требует решения (resolution), known_error — обходного решения (workaround).
func (s Store) Transition(ctx context.Context, tx pgx.Tx, tenant, actor, id, revision, to, text string) (Detail, error) {
	d, e := s.Detail(ctx, tx, tenant, id, true)
	if e != nil {
		return d, e
	}
	if d.Revision != revision {
		return d, domain.Revision
	}
	allowed := false
	for _, x := range transitions[d.Kind][d.State] {
		allowed = allowed || x == to
	}
	if !allowed {
		return d, domain.Conflict
	}
	note, ok := clean(text, 0, 4000)
	if !ok || (to == "resolved" || to == "known_error" || to == "fulfilled") && note == "" {
		return d, domain.Invalid
	}
	reopen := (d.State == "resolved" || d.State == "fulfilled") && to != "closed"
	tag, e := tx.Exec(ctx, `UPDATE itsm.tickets SET state=$4,updated_at=now(),revision=revision+1,
resolution=CASE WHEN $4 IN ('resolved','fulfilled') THEN $5 ELSE resolution END,
workaround=CASE WHEN $4='known_error' THEN $5 ELSE workaround END,
resolved_at=CASE WHEN $4 IN ('resolved','fulfilled') THEN now() WHEN $6 THEN NULL ELSE resolved_at END,
closed_at=CASE WHEN $4 IN ('closed','cancelled') THEN now() ELSE closed_at END,
reopen_count=reopen_count+CASE WHEN $6 THEN 1 ELSE 0 END
WHERE tenant_id=$1 AND ticket_id=$2 AND revision::text=$3`, tenant, id, revision, to, nullable(note), reopen)
	if e != nil {
		return d, e
	}
	if tag.RowsAffected() == 0 {
		return d, domain.Revision
	}
	if e = event(ctx, tx, tenant, id, actor, "state", true, map[string]any{"from": d.State, "to": to, "reopen": reopen}, nullable(note)); e != nil {
		return d, e
	}
	return s.Detail(ctx, tx, tenant, id, true)
}

// Assign назначает исполнителя (человек) и/или команду; новый инцидент становится assigned. Ревизия обязательна:
// два оператора, одновременно берущие обращение, — назначение получает один (W3-03).
func (s Store) Assign(ctx context.Context, tx pgx.Tx, tenant, actor, id, revision, assignee, team, reason string) (Detail, error) {
	if assignee == "" && team == "" {
		return Detail{}, domain.Invalid
	}
	if assignee != "" {
		if e := activeSubject(ctx, tx, tenant, assignee, "person"); e != nil {
			return Detail{}, e
		}
	}
	if team != "" {
		if e := activeSubject(ctx, tx, tenant, team, "team"); e != nil {
			return Detail{}, e
		}
	}
	note, ok := clean(reason, 0, 1000)
	if !ok {
		return Detail{}, domain.Invalid
	}
	tag, e := tx.Exec(ctx, `UPDATE itsm.tickets SET assignee_id=COALESCE($4,assignee_id),team_id=COALESCE($5,team_id),updated_at=now(),revision=revision+1,
state=CASE WHEN kind='incident' AND state='new' THEN 'assigned' ELSE state END
WHERE tenant_id=$1 AND ticket_id=$2 AND revision::text=$3 AND state NOT IN ('closed','cancelled')`, tenant, id, revision, nullable(assignee), nullable(team))
	if e != nil {
		return Detail{}, pgConflict(e)
	}
	if tag.RowsAffected() == 0 {
		cur, e := s.Detail(ctx, tx, tenant, id, true)
		if e != nil {
			return cur, e
		}
		if cur.State == "closed" || cur.State == "cancelled" {
			return cur, domain.Conflict
		}
		return cur, domain.Revision
	}
	if e = event(ctx, tx, tenant, id, actor, "assigned", true, map[string]any{"assignee_id": nullable(assignee), "team_id": nullable(team)}, nullable(note)); e != nil {
		return Detail{}, e
	}
	return s.Detail(ctx, tx, tenant, id, true)
}

// Comment — комментарий; public=false — внутренний (заявителю не виден).
func (s Store) Comment(ctx context.Context, tx pgx.Tx, tenant, actor, id, text string, public bool) (Detail, error) {
	t, ok := clean(text, 1, 8000)
	if !ok {
		return Detail{}, domain.Invalid
	}
	tag, e := tx.Exec(ctx, "UPDATE itsm.tickets SET updated_at=now() WHERE tenant_id=$1 AND ticket_id=$2", tenant, id)
	if e != nil {
		return Detail{}, e
	}
	if tag.RowsAffected() == 0 {
		return Detail{}, domain.NotFound
	}
	if e = event(ctx, tx, tenant, id, actor, "comment", public, map[string]any{}, &t); e != nil {
		return Detail{}, e
	}
	return s.Detail(ctx, tx, tenant, id, true)
}

// Link связывает обращение с активом, сервисом, другим обращением или складским движением (цель должна существовать
// в этой организации). Повтор идемпотентен.
func (Store) Link(ctx context.Context, tx pgx.Tx, tenant, actor, id, kind, target string) error {
	if !identifier.Valid(id) || !identifier.Valid(target) || target == id {
		return domain.Invalid
	}
	var ok bool
	var e error
	switch kind {
	case "asset":
		e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM assets.assets WHERE tenant_id=$1 AND asset_uid=$2 AND merged_into IS NULL)", tenant, target).Scan(&ok)
	case "service":
		e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM cmdb.services WHERE tenant_id=$1 AND service_uid=$2)", tenant, target).Scan(&ok)
	case "ticket":
		e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM itsm.tickets WHERE tenant_id=$1 AND ticket_id=$2)", tenant, target).Scan(&ok)
	case "movement":
		e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM warehouse.movements WHERE tenant_id=$1 AND movement_id=$2)", tenant, target).Scan(&ok)
	default:
		return domain.Invalid
	}
	if e != nil {
		return e
	}
	if !ok {
		return domain.Invalid
	}
	tag, e := tx.Exec(ctx, "INSERT INTO itsm.ticket_links(tenant_id,ticket_id,target_kind,target_id,created_by) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING", tenant, id, kind, target, actor)
	if e != nil {
		return pgConflict(e)
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	return event(ctx, tx, tenant, id, actor, "linked", true, map[string]any{"target_kind": kind, "target_id": target}, nil)
}

// MySubject — запись оргструктуры (человек), связанная с учётной записью пользователя (для «взять себе», «мои»).
func (Store) MySubject(ctx context.Context, tx pgx.Tx, tenant, user string) (string, error) {
	var id string
	e := tx.QueryRow(ctx, "SELECT subject_id::text FROM responsibility.subjects WHERE tenant_id=$1 AND user_id=$2 AND active AND kind='person' LIMIT 1", tenant, user).Scan(&id)
	if errors.Is(e, pgx.ErrNoRows) {
		return "", ErrNoSubject
	}
	return id, e
}

// ErrNoSubject — у пользователя нет записи в оргструктуре: «взять себе» невозможно (назначить можно вручную).
var ErrNoSubject = fmt.Errorf("itsm: user has no person subject: %w", domain.Invalid)
