package itsm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// Каталог услуг и заявки (C48; AC W3-05). Услуга — форма полей, согласующий (человек или команда), команда-исполнитель
// и, для складской услуги, позиция склада. Исполнение складской услуги собирает слой приложения: выдача со склада,
// связь с движением и переход «исполнено» — в одной транзакции (повтор — конфликт ревизии/состояния).

// Field — поле формы услуги: text, textarea или select (с вариантами).
type Field struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Type     string   `json:"type"`
	Required bool     `json:"required"`
	Options  []string `json:"options"`
}

type CatalogItem struct {
	ID            string  `json:"item_id"`
	Name          string  `json:"name"`
	Description   string  `json:"description"`
	Form          []Field `json:"form"`
	Approver      *string `json:"approver_id"`
	Team          *string `json:"team_id"`
	WarehouseItem *string `json:"warehouse_item_id"`
	Active        bool    `json:"active"`
	Revision      string  `json:"revision"`
}

// Approval — решение согласующего.
type Approval struct {
	Approver  *string   `json:"approver_id"`
	Decision  string    `json:"decision"`
	Comment   *string   `json:"comment"`
	DecidedBy string    `json:"decided_by"`
	DecidedAt time.Time `json:"decided_at"`
}

// Request — сведения заявки в карточке обращения (null у остальных видов).
type Request struct {
	CatalogItem   string            `json:"catalog_item_id"`
	CatalogName   string            `json:"catalog_name"`
	Values        map[string]string `json:"form_values"`
	Approver      *string           `json:"approver_id"`
	WarehouseItem *string           `json:"warehouse_item_id"`
	Approval      *Approval         `json:"approval"`
}

var fieldKey = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

func validForm(form []Field) bool {
	if len(form) > 20 {
		return false
	}
	seen := map[string]bool{}
	for i, f := range form {
		label, ok := clean(f.Label, 1, 128)
		if !ok || !fieldKey.MatchString(f.Key) || seen[f.Key] {
			return false
		}
		seen[f.Key] = true
		form[i].Label = label
		switch f.Type {
		case "text", "textarea":
			if len(f.Options) != 0 {
				return false
			}
			form[i].Options = []string{}
		case "select":
			if len(f.Options) < 1 || len(f.Options) > 50 {
				return false
			}
			for _, o := range f.Options {
				if _, ok := clean(o, 1, 128); !ok || o != strings.TrimSpace(o) {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

func optional(ctx context.Context, tx pgx.Tx, tenant string, id *string, kind string) (*string, error) {
	if id == nil || *id == "" {
		return nil, nil
	}
	if !identifier.Valid(*id) {
		return nil, domain.Invalid
	}
	return id, activeSubject(ctx, tx, tenant, *id, kind)
}

// SaveCatalogItem создаёт услугу (ID пуст) или меняет её по ревизии.
func (s Store) SaveCatalogItem(ctx context.Context, tx pgx.Tx, tenant string, it CatalogItem) (CatalogItem, error) {
	name, ok1 := clean(it.Name, 1, 128)
	desc, ok2 := clean(it.Description, 0, 4000)
	if it.Form == nil {
		it.Form = []Field{}
	}
	if !ok1 || !ok2 || !validForm(it.Form) {
		return it, domain.Invalid
	}
	approver, e := optional(ctx, tx, tenant, it.Approver, "")
	if e != nil {
		return it, e
	}
	team, e := optional(ctx, tx, tenant, it.Team, "team")
	if e != nil {
		return it, e
	}
	var wh *string
	if it.WarehouseItem != nil && *it.WarehouseItem != "" {
		if !identifier.Valid(*it.WarehouseItem) {
			return it, domain.Invalid
		}
		var exists bool
		if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM warehouse.items WHERE tenant_id=$1 AND item_id=$2 AND active)", tenant, *it.WarehouseItem).Scan(&exists); e != nil {
			return it, e
		}
		if !exists {
			return it, domain.Invalid
		}
		wh = it.WarehouseItem
	}
	form, _ := json.Marshal(it.Form)
	if it.ID == "" {
		it.ID = identifier.New()
		if _, e = tx.Exec(ctx, `INSERT INTO itsm.catalog_items(tenant_id,item_id,name,description,form,approver_id,team_id,warehouse_item_id,active)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,true)`, tenant, it.ID, name, desc, form, approver, team, wh); e != nil {
			return it, pgConflict(e)
		}
		return s.catalogItem(ctx, tx, tenant, it.ID)
	}
	if !identifier.Valid(it.ID) {
		return it, domain.NotFound
	}
	tag, e := tx.Exec(ctx, `UPDATE itsm.catalog_items SET name=$4,description=$5,form=$6,approver_id=$7,team_id=$8,warehouse_item_id=$9,active=$10,revision=revision+1
WHERE tenant_id=$1 AND item_id=$2 AND revision::text=$3`, tenant, it.ID, it.Revision, name, desc, form, approver, team, wh, it.Active)
	if e != nil {
		return it, pgConflict(e)
	}
	if tag.RowsAffected() == 0 {
		if _, e = s.catalogItem(ctx, tx, tenant, it.ID); e != nil {
			return it, e
		}
		return it, domain.Revision
	}
	return s.catalogItem(ctx, tx, tenant, it.ID)
}

func scanCatalog(r pgx.Row, it *CatalogItem) error {
	var form []byte
	if e := r.Scan(&it.ID, &it.Name, &it.Description, &form, &it.Approver, &it.Team, &it.WarehouseItem, &it.Active, &it.Revision); e != nil {
		return e
	}
	return json.Unmarshal(form, &it.Form)
}

func (Store) catalogItem(ctx context.Context, tx pgx.Tx, tenant, id string) (CatalogItem, error) {
	var it CatalogItem
	e := scanCatalog(tx.QueryRow(ctx, `SELECT item_id::text,name,description,form,approver_id::text,team_id::text,warehouse_item_id::text,active,revision::text
FROM itsm.catalog_items WHERE tenant_id=$1 AND item_id=$2`, tenant, id), &it)
	if errors.Is(e, pgx.ErrNoRows) {
		return it, domain.NotFound
	}
	return it, e
}

// Catalog — услуги каталога (activeOnly — для портала).
func (Store) Catalog(ctx context.Context, tx pgx.Tx, tenant string, activeOnly bool) ([]CatalogItem, error) {
	rows, e := tx.Query(ctx, `SELECT item_id::text,name,description,form,approver_id::text,team_id::text,warehouse_item_id::text,active,revision::text
FROM itsm.catalog_items WHERE tenant_id=$1 AND (active OR NOT $2) ORDER BY active DESC, lower(name)`, tenant, activeOnly)
	if e != nil {
		return nil, e
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (CatalogItem, error) {
		var it CatalogItem
		return it, scanCatalog(r, &it)
	})
}

// CreateRequest — заявка заявителя по услуге каталога: значения формы проверяются по полям услуги; с согласующим —
// pending_approval, без — сразу in_fulfillment; команда-исполнитель — из услуги.
func (s Store) CreateRequest(ctx context.Context, tx pgx.Tx, tenant, actor, requester, item string, values map[string]string, urgency int) (Detail, error) {
	if !identifier.Valid(item) {
		return Detail{}, domain.Invalid
	}
	it, e := s.catalogItem(ctx, tx, tenant, item)
	if errors.Is(e, domain.NotFound) || e == nil && !it.Active {
		return Detail{}, domain.Invalid
	}
	if e != nil {
		return Detail{}, e
	}
	if urgency == 0 {
		urgency = 3
	}
	known := map[string]bool{}
	var lines []string
	clean2 := map[string]string{}
	for _, f := range it.Form {
		known[f.Key] = true
		v, ok := clean(values[f.Key], 0, 1000)
		if !ok || f.Required && v == "" {
			return Detail{}, domain.Invalid
		}
		if f.Type == "select" && v != "" {
			found := false
			for _, o := range f.Options {
				found = found || o == v
			}
			if !found {
				return Detail{}, domain.Invalid
			}
		}
		if v != "" {
			clean2[f.Key] = v
			lines = append(lines, f.Label+": "+v)
		}
	}
	for k := range values {
		if !known[k] {
			return Detail{}, domain.Invalid
		}
	}
	state := "in_fulfillment"
	if it.Approver != nil {
		state = "pending_approval"
	}
	raw, _ := json.Marshal(clean2)
	return s.create(ctx, tx, tenant, actor, Input{Kind: "request", Title: it.Name, Description: strings.Join(lines, "\n"), Impact: 3, Urgency: urgency, Requester: requester},
		state, &it.ID, raw, it.Team)
}

// ErrNotApprover — пользователь не согласующий этой заявки (не человек-согласующий и не член команды-согласующей).
var ErrNotApprover = fmt.Errorf("itsm: not an approver of this request: %w", domain.Invalid)

// Approve — решение по заявке в pending_approval: согласовано → in_fulfillment, отклонено (с причиной) → rejected.
// Решает согласующий (человек или член команды) или администратор (admin=true); решение одно (ревизия).
func (s Store) Approve(ctx context.Context, tx pgx.Tx, tenant, actor, me, id, revision string, admin, approve bool, comment string) (Detail, error) {
	d, e := s.Detail(ctx, tx, tenant, id, true)
	if e != nil {
		return d, e
	}
	var approver *string // NULL — согласующего убрали из услуги после подачи заявки или изменение (решает администратор)
	if d.Kind == "change" {
		if !admin {
			return Detail{}, ErrNotApprover // изменения согласует администратор (CAB)
		}
		if d.State != "submitted" {
			return d, domain.Conflict
		}
	} else {
		e = tx.QueryRow(ctx, `SELECT c.approver_id::text FROM itsm.tickets t JOIN itsm.catalog_items c ON c.tenant_id=t.tenant_id AND c.item_id=t.catalog_item_id
	WHERE t.tenant_id=$1 AND t.ticket_id=$2 AND ($3::boolean OR c.approver_id::text=$4 OR EXISTS(SELECT 1 FROM responsibility.team_members m
	 WHERE m.tenant_id=c.tenant_id AND m.team_id=c.approver_id AND m.person_id::text=$4 AND m.valid_to IS NULL))`, tenant, id, admin, me).Scan(&approver)
		if errors.Is(e, pgx.ErrNoRows) {
			return Detail{}, ErrNotApprover
		}
		if e != nil {
			return d, e
		}
	}
	if d.Kind == "request" && d.State != "pending_approval" {
		return d, domain.Conflict
	}
	if d.Revision != revision {
		return d, domain.Revision
	}
	note, ok := clean(comment, 0, 2000)
	if !ok || !approve && note == "" {
		return d, domain.Invalid
	}
	decision, to := "approved", "in_fulfillment"
	if d.Kind == "change" {
		to = "approved"
	}
	if !approve {
		decision, to = "rejected", "rejected"
	}
	tag, e := tx.Exec(ctx, `UPDATE itsm.tickets SET state=$4,updated_at=now(),revision=revision+1,closed_at=CASE WHEN $4='rejected' THEN now() ELSE closed_at END
WHERE tenant_id=$1 AND ticket_id=$2 AND revision::text=$3 AND state IN ('pending_approval','submitted')`, tenant, id, revision, to)
	if e != nil {
		return d, e
	}
	if tag.RowsAffected() == 0 {
		return d, domain.Revision
	}
	if _, e = tx.Exec(ctx, "INSERT INTO itsm.approvals(tenant_id,ticket_id,approver_id,decision,comment,decided_by) VALUES($1,$2,$3,$4,$5,$6)",
		tenant, id, approver, decision, nullable(note), actor); e != nil {
		return d, pgConflict(e)
	}
	if e = event(ctx, tx, tenant, id, actor, "approval", true, map[string]any{"decision": decision, "from": d.State, "to": to}, nullable(note)); e != nil {
		return d, e
	}
	return s.Detail(ctx, tx, tenant, id, true)
}

// PendingApprovals — заявки, ждущие решения этого человека (лично или как члена команды-согласующей).
func (Store) PendingApprovals(ctx context.Context, tx pgx.Tx, tenant, me string) ([]Ticket, error) {
	rows, e := tx.Query(ctx, `SELECT t.ticket_id::text,t.kind,t.number,t.title,t.description,t.impact,t.urgency,t.priority,t.state,t.requester_id::text,t.assignee_id::text,t.team_id::text,
t.resolution,t.workaround,t.reopen_count,t.created_by,t.created_at,t.updated_at,t.resolved_at,t.closed_at,t.revision::text FROM itsm.tickets t JOIN itsm.catalog_items c ON c.tenant_id=t.tenant_id AND c.item_id=t.catalog_item_id
WHERE t.tenant_id=$1 AND t.state='pending_approval' AND (c.approver_id::text=$2 OR EXISTS(SELECT 1 FROM responsibility.team_members m
 WHERE m.tenant_id=c.tenant_id AND m.team_id=c.approver_id AND m.person_id::text=$2 AND m.valid_to IS NULL)) ORDER BY t.created_at LIMIT 200`, tenant, me)
	if e != nil {
		return nil, e
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Ticket, error) {
		var t Ticket
		return t, scanTicket(r, &t)
	})
}

// Fulfilled — отметка исполнения складом: связь с движением и переход in_fulfillment → fulfilled (по ревизии);
// повтор — конфликт состояния или ревизии, движение откатывается вместе с транзакцией.
func (s Store) Fulfilled(ctx context.Context, tx pgx.Tx, tenant, actor, id, revision, movement, act, text string) (Detail, error) {
	if e := s.Link(ctx, tx, tenant, actor, id, "movement", movement); e != nil {
		return Detail{}, e
	}
	if strings.TrimSpace(text) == "" {
		text = "Выдано со склада, акт " + act
	}
	if _, e := s.Transition(ctx, tx, tenant, actor, id, revision, "fulfilled", text); e != nil {
		return Detail{}, e
	}
	if e := event(ctx, tx, tenant, id, actor, "fulfilled", true, map[string]any{"movement_id": movement, "act_no": act}, nil); e != nil {
		return Detail{}, e
	}
	return s.Detail(ctx, tx, tenant, id, true)
}
