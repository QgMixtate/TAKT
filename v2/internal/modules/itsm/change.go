package itsm

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
)

// Изменения (C49; AC W3-06): окно, риск, план работ и отката; затронутые активы и сервисы — связи обращения.
// Окна изменений на одном активе/сервисе не пересекаются без явного подтверждения при планировании (scheduled).

type Window struct {
	StartsAt           time.Time `json:"starts_at"`
	EndsAt             time.Time `json:"ends_at"`
	Risk               string    `json:"risk"`
	Plan               string    `json:"plan"`
	RollbackPlan       string    `json:"rollback_plan"`
	ConflictsConfirmed bool      `json:"conflicts_confirmed"`
}

// WindowConflict — другое активное изменение с пересекающимся окном на общем активе/сервисе.
type WindowConflict struct {
	TicketID string    `json:"ticket_id"`
	Number   string    `json:"number"`
	Title    string    `json:"title"`
	State    string    `json:"state"`
	StartsAt time.Time `json:"starts_at"`
	EndsAt   time.Time `json:"ends_at"`
}

type Change struct {
	Window    *Window          `json:"window"`
	Approval  *Approval        `json:"approval"`
	Conflicts []WindowConflict `json:"conflicts"`
}

// ErrNoWindow — изменение без окна нельзя подать на согласование и запланировать.
var ErrNoWindow = fmt.Errorf("itsm: change has no window: %w", domain.Invalid)

// WindowConflictError — окно пересекается с другими изменениями; планирование — только с подтверждением.
type WindowConflictError struct{ Conflicts []WindowConflict }

func (e *WindowConflictError) Error() string {
	return "itsm: change window conflicts with other changes"
}
func (e *WindowConflictError) Unwrap() error { return domain.Conflict }

func approvalOf(ctx context.Context, tx pgx.Tx, tenant, id string) (*Approval, error) {
	a := &Approval{}
	e := tx.QueryRow(ctx, "SELECT approver_id::text,decision,comment,decided_by,decided_at FROM itsm.approvals WHERE tenant_id=$1 AND ticket_id=$2", tenant, id).Scan(&a.Approver, &a.Decision, &a.Comment, &a.DecidedBy, &a.DecidedAt)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	return a, nil
}

func changeInfo(ctx context.Context, tx pgx.Tx, tenant, id string) (*Change, error) {
	c := &Change{Conflicts: []WindowConflict{}}
	w := &Window{}
	e := tx.QueryRow(ctx, "SELECT starts_at,ends_at,risk,plan,rollback_plan,conflicts_confirmed FROM itsm.change_windows WHERE tenant_id=$1 AND ticket_id=$2", tenant, id).
		Scan(&w.StartsAt, &w.EndsAt, &w.Risk, &w.Plan, &w.RollbackPlan, &w.ConflictsConfirmed)
	switch {
	case errors.Is(e, pgx.ErrNoRows):
	case e != nil:
		return nil, e
	default:
		c.Window = w
		rows, e := tx.Query(ctx, `SELECT DISTINCT o.ticket_id::text,o.number,o.title,o.state,ow.starts_at,ow.ends_at FROM itsm.change_windows w
JOIN itsm.ticket_links l ON l.tenant_id=w.tenant_id AND l.ticket_id=w.ticket_id AND l.target_kind IN ('asset','service')
JOIN itsm.ticket_links ol ON ol.tenant_id=l.tenant_id AND ol.target_kind=l.target_kind AND ol.target_id=l.target_id AND ol.ticket_id<>w.ticket_id
JOIN itsm.tickets o ON o.tenant_id=ol.tenant_id AND o.ticket_id=ol.ticket_id AND o.kind='change' AND o.state IN ('submitted','approved','scheduled','in_progress')
JOIN itsm.change_windows ow ON ow.tenant_id=o.tenant_id AND ow.ticket_id=o.ticket_id AND ow.starts_at<w.ends_at AND ow.ends_at>w.starts_at
WHERE w.tenant_id=$1 AND w.ticket_id=$2 ORDER BY ow.starts_at,o.number`, tenant, id)
		if e != nil {
			return nil, e
		}
		if c.Conflicts, e = pgx.CollectRows(rows, func(r pgx.CollectableRow) (WindowConflict, error) {
			var x WindowConflict
			return x, r.Scan(&x.TicketID, &x.Number, &x.Title, &x.State, &x.StartsAt, &x.EndsAt)
		}); e != nil {
			return nil, e
		}
		if c.Conflicts == nil {
			c.Conflicts = []WindowConflict{}
		}
	}
	c.Approval, e = approvalOf(ctx, tx, tenant, id)
	return c, e
}

var risks = map[string]bool{"low": true, "medium": true, "high": true}

// SetWindow задаёт окно изменения (черновик или согласованное, ещё не запланированное); ревизия обязательна.
func (s Store) SetWindow(ctx context.Context, tx pgx.Tx, tenant, actor, id, revision string, w Window) (Detail, error) {
	d, e := s.Detail(ctx, tx, tenant, id, true)
	if e != nil {
		return d, e
	}
	if d.Kind != "change" || d.State != "draft" && d.State != "approved" {
		return d, domain.Conflict
	}
	if d.Revision != revision {
		return d, domain.Revision
	}
	plan, ok1 := clean(w.Plan, 1, 8000)
	back, ok2 := clean(w.RollbackPlan, 1, 8000)
	if !ok1 || !ok2 || !risks[w.Risk] || !w.EndsAt.After(w.StartsAt) || w.EndsAt.Sub(w.StartsAt) > 31*24*time.Hour {
		return d, domain.Invalid
	}
	if _, e = tx.Exec(ctx, `INSERT INTO itsm.change_windows(tenant_id,ticket_id,starts_at,ends_at,risk,plan,rollback_plan) VALUES($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT (tenant_id,ticket_id) DO UPDATE SET starts_at=EXCLUDED.starts_at,ends_at=EXCLUDED.ends_at,risk=EXCLUDED.risk,plan=EXCLUDED.plan,
rollback_plan=EXCLUDED.rollback_plan,conflicts_confirmed=false,updated_at=now()`, tenant, id, w.StartsAt, w.EndsAt, w.Risk, plan, back); e != nil {
		return d, pgConflict(e)
	}
	tag, e := tx.Exec(ctx, "UPDATE itsm.tickets SET updated_at=now(),revision=revision+1 WHERE tenant_id=$1 AND ticket_id=$2 AND revision::text=$3", tenant, id, revision)
	if e != nil {
		return d, e
	}
	if tag.RowsAffected() == 0 {
		return d, domain.Revision
	}
	if e = event(ctx, tx, tenant, id, actor, "window", true, map[string]any{"starts_at": w.StartsAt, "ends_at": w.EndsAt, "risk": w.Risk}, nil); e != nil {
		return d, e
	}
	return s.Detail(ctx, tx, tenant, id, true)
}

// CalendarEntry — изменение в календаре окон.
type CalendarEntry struct {
	TicketID string    `json:"ticket_id"`
	Number   string    `json:"number"`
	Title    string    `json:"title"`
	State    string    `json:"state"`
	Risk     string    `json:"risk"`
	StartsAt time.Time `json:"starts_at"`
	EndsAt   time.Time `json:"ends_at"`
	Targets  []Link    `json:"targets"`
}

// Calendar — окна изменений, пересекающие период [from, to) (не более 92 дней), кроме отменённых и отклонённых.
func (Store) Calendar(ctx context.Context, tx pgx.Tx, tenant string, from, to time.Time) ([]CalendarEntry, error) {
	if !to.After(from) || to.Sub(from) > 92*24*time.Hour {
		return nil, domain.Invalid
	}
	rows, e := tx.Query(ctx, `SELECT t.ticket_id::text,t.number,t.title,t.state,w.risk,w.starts_at,w.ends_at,
COALESCE((SELECT jsonb_agg(jsonb_build_object('target_kind',l.target_kind,'target_id',l.target_id,'label',COALESCE(CASE l.target_kind
 WHEN 'service' THEN (SELECT s.name FROM cmdb.services s WHERE s.tenant_id=l.tenant_id AND s.service_uid=l.target_id)
 WHEN 'asset' THEN COALESCE(NULLIF((SELECT b.display_name FROM assets.asset_business_fields b WHERE b.tenant_id=l.tenant_id AND b.asset_uid=l.target_id),''),(SELECT h.name FROM cmdb.host_registry h WHERE h.tenant_id=l.tenant_id AND h.asset_uid=l.target_id)) END,'')) ORDER BY l.target_kind,l.target_id)
 FROM itsm.ticket_links l WHERE l.tenant_id=t.tenant_id AND l.ticket_id=t.ticket_id AND l.target_kind IN ('asset','service')),'[]'::jsonb)
FROM itsm.change_windows w JOIN itsm.tickets t ON t.tenant_id=w.tenant_id AND t.ticket_id=w.ticket_id
WHERE w.tenant_id=$1 AND w.starts_at<$3 AND w.ends_at>$2 AND t.state NOT IN ('cancelled','rejected') ORDER BY w.starts_at,t.number LIMIT 1000`, tenant, from, to)
	if e != nil {
		return nil, e
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (CalendarEntry, error) {
		var c CalendarEntry
		return c, r.Scan(&c.TicketID, &c.Number, &c.Title, &c.State, &c.Risk, &c.StartsAt, &c.EndsAt, &c.Targets)
	})
}
