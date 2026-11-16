package app

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/itsm"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/warehouse"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// Обращения ITSM (волна 3; decisions/C46-w3-itsm-scope-and-model.md). Права: itsm:read — все сотрудники ИТ,
// itsm:write — оператор/администратор, itsm:admin — администратор. Роль «заявитель» (портал, вход по AD) — C48.

func (r *Registry) itsmDo(w http.ResponseWriter, req *http.Request, status int, permission string, fn func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error)) {
	ctx, cancel, id := cmdbContext(req)
	defer cancel()
	tx, e := r.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		registryError(w, e)
		return
	}
	defer tx.Rollback(ctx)
	if _, e = r.Auth.Authorize(ctx, tx, id.CredentialID, id.TenantID, permission); e != nil {
		cmdbError(w, req, e)
		return
	}
	out, e := fn(ctx, tx, id)
	if e == nil {
		e = tx.Commit(ctx)
	}
	var incompatible *warehouse.IncompatibleError
	var reserved *warehouse.ReservedError
	var windowConflict *itsm.WindowConflictError
	switch {
	case errors.As(e, &reserved):
		access.APIError(w, 409, "UNIT_RESERVED")
	case errors.As(e, &incompatible):
		access.APIError(w, 409, "INCOMPATIBLE_COMPONENT")
	case errors.Is(e, warehouse.ErrInventoryOpen):
		access.APIError(w, 409, "LOCATION_UNDER_INVENTORY")
	case errors.As(e, &windowConflict):
		access.APIError(w, 409, "WINDOW_CONFLICT") // окно пересекается с другими изменениями: подтвердите явно
	case errors.Is(e, itsm.ErrNoWindow):
		access.APIError(w, 422, "NO_CHANGE_WINDOW")
	case errors.Is(e, itsm.ErrNotApprover):
		access.APIError(w, 403, "NOT_APPROVER") // решает только согласующий (человек, член команды) или администратор
	case errors.Is(e, itsm.ErrNoSubject):
		access.APIError(w, 422, "NO_PERSON_SUBJECT") // у пользователя нет записи в оргструктуре
	case e != nil:
		cmdbError(w, req, e)
	default:
		registryJSONStatus(w, status, out)
	}
}

func (r *Registry) itsmHandlers() map[string]route51 {
	st := itsm.Store{}
	h := map[string]route51{}
	actor := func(id accessport.Identity) string { return "user:" + id.UserID }
	h["GET /api/v1/itsm/tickets"] = route51{"itsm:read", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q, ok := queryOnly(w, req, "kind", "state", "assignee", "team", "requester", "q", "mine", "limit")
		if !ok {
			return
		}
		r.itsmDo(w, req, 200, "itsm:read", func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
			n, ok := limitOf(q, 100, 500)
			if !ok {
				return nil, domain.Invalid
			}
			f := itsm.Filter{Kind: q.Get("kind"), State: q.Get("state"), Assignee: q.Get("assignee"), Team: q.Get("team"), Requester: q.Get("requester"), Query: q.Get("q")}
			if q.Get("mine") == "true" {
				me, e := st.MySubject(ctx, tx, id.TenantID, id.UserID)
				if e != nil {
					return nil, e
				}
				f.Assignee = me
			}
			items, e := st.List(ctx, tx, id.TenantID, f, n)
			return map[string]any{"items": items}, e
		})
	})}
	h["GET /api/v1/itsm/tickets/{ticket_id}"] = route51{"itsm:read", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		r.itsmDo(w, req, 200, "itsm:read", func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
			return st.Detail(ctx, tx, id.TenantID, req.PathValue("ticket_id"), true)
		})
	})}
	post := func(route string, status int, newBody func() any, fn func(ctx context.Context, tx pgx.Tx, id accessport.Identity, req *http.Request, body any) (itsm.Detail, string, error)) {
		h[route] = route51{"itsm:write", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			body := newBody()
			if !readOperationBody(w, req, body) {
				return
			}
			r.itsmDo(w, req, status, "itsm:write", func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
				d, action, e := fn(ctx, tx, id, req, body)
				if e == nil {
					e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, action, "ticket", d.ID)
				}
				return d, e
			})
		})}
	}
	post("POST /api/v1/itsm/tickets", 201, func() any { return &itsm.Input{} }, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, _ *http.Request, body any) (itsm.Detail, string, error) {
		d, e := st.Create(ctx, tx, id.TenantID, actor(id), *body.(*itsm.Input))
		return d, "itsm.ticket_created", e
	})
	type transition struct {
		Revision string `json:"revision"`
		To       string `json:"to"`
		Text     string `json:"text"`
		// ConfirmConflicts — запланировать изменение, несмотря на пересечение окон (W3-06)
		ConfirmConflicts bool `json:"confirm_conflicts"`
	}
	post("POST /api/v1/itsm/tickets/{ticket_id}/transition", 200, func() any { return &transition{} }, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, req *http.Request, body any) (itsm.Detail, string, error) {
		b := body.(*transition)
		if b.ConfirmConflicts {
			d, e := st.TransitionConfirmed(ctx, tx, id.TenantID, actor(id), req.PathValue("ticket_id"), b.Revision, b.To, b.Text)
			return d, "itsm.ticket_" + b.To, e
		}
		d, e := st.Transition(ctx, tx, id.TenantID, actor(id), req.PathValue("ticket_id"), b.Revision, b.To, b.Text)
		return d, "itsm.ticket_" + b.To, e
	})
	type assign struct {
		Revision string `json:"revision"`
		Assignee string `json:"assignee_id"`
		Team     string `json:"team_id"`
		Reason   string `json:"reason"`
		Me       bool   `json:"me"` // «взять себе»
	}
	post("POST /api/v1/itsm/tickets/{ticket_id}/assign", 200, func() any { return &assign{} }, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, req *http.Request, body any) (itsm.Detail, string, error) {
		b := body.(*assign)
		if b.Me {
			if b.Assignee != "" {
				return itsm.Detail{}, "", domain.Invalid
			}
			me, e := st.MySubject(ctx, tx, id.TenantID, id.UserID)
			if e != nil {
				return itsm.Detail{}, "", e
			}
			b.Assignee = me
		}
		d, e := st.Assign(ctx, tx, id.TenantID, actor(id), req.PathValue("ticket_id"), b.Revision, b.Assignee, b.Team, b.Reason)
		return d, "itsm.ticket_assigned", e
	})
	type comment struct {
		Text     string `json:"text"`
		Internal bool   `json:"internal"`
	}
	post("POST /api/v1/itsm/tickets/{ticket_id}/comments", 201, func() any { return &comment{} }, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, req *http.Request, body any) (itsm.Detail, string, error) {
		b := body.(*comment)
		d, e := st.Comment(ctx, tx, id.TenantID, actor(id), req.PathValue("ticket_id"), b.Text, !b.Internal)
		return d, "itsm.ticket_commented", e
	})
	type link struct {
		Kind   string `json:"target_kind"`
		Target string `json:"target_id"`
	}
	post("POST /api/v1/itsm/tickets/{ticket_id}/links", 201, func() any { return &link{} }, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, req *http.Request, body any) (itsm.Detail, string, error) {
		b := body.(*link)
		ticket := req.PathValue("ticket_id")
		if !identifier.Valid(ticket) {
			return itsm.Detail{}, "", domain.NotFound
		}
		if _, e := st.Detail(ctx, tx, id.TenantID, ticket, true); e != nil {
			return itsm.Detail{}, "", e
		}
		if e := st.Link(ctx, tx, id.TenantID, actor(id), ticket, b.Kind, b.Target); e != nil {
			return itsm.Detail{}, "", e
		}
		d, e := st.Detail(ctx, tx, id.TenantID, ticket, true)
		return d, "itsm.ticket_linked", e
	})
	// Изменения (C49): окно и календарь окон.
	type window struct {
		Revision string `json:"revision"`
		itsm.Window
	}
	post("POST /api/v1/itsm/tickets/{ticket_id}/window", 200, func() any { return &window{} }, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, req *http.Request, body any) (itsm.Detail, string, error) {
		b := body.(*window)
		d, e := st.SetWindow(ctx, tx, id.TenantID, actor(id), req.PathValue("ticket_id"), b.Revision, b.Window)
		return d, "itsm.change_window_set", e
	})
	h["GET /api/v1/itsm/changes/calendar"] = route51{"itsm:read", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q, ok := queryOnly(w, req, "from", "to")
		if !ok {
			return
		}
		r.itsmDo(w, req, 200, "itsm:read", func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
			from, e1 := time.Parse(time.RFC3339, q.Get("from"))
			to, e2 := time.Parse(time.RFC3339, q.Get("to"))
			if e1 != nil || e2 != nil {
				return nil, domain.Invalid
			}
			items, e := st.Calendar(ctx, tx, id.TenantID, from, to)
			return map[string]any{"items": items}, e
		})
	})}
	// Каталог услуг (C48): чтение — itsm:read, изменение — администратор.
	h["GET /api/v1/itsm/catalog"] = route51{"itsm:read", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		r.itsmDo(w, req, 200, "itsm:read", func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
			items, e := st.Catalog(ctx, tx, id.TenantID, false)
			return map[string]any{"items": items}, e
		})
	})}
	saveCatalog := func(status int) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			var body itsm.CatalogItem
			if !readOperationBody(w, req, &body) {
				return
			}
			r.itsmDo(w, req, status, "itsm:admin", func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
				body.ID = req.PathValue("item_id")
				if body.ID == "" {
					body.Active = true
				}
				it, e := st.SaveCatalogItem(ctx, tx, id.TenantID, body)
				if e == nil {
					e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "itsm.catalog_saved", "catalog_item", it.ID)
				}
				return it, e
			})
		}
	}
	h["POST /api/v1/itsm/catalog"] = route51{"itsm:admin", saveCatalog(201)}
	h["POST /api/v1/itsm/catalog/{item_id}"] = route51{"itsm:admin", saveCatalog(200)}
	type approval struct {
		Revision string `json:"revision"`
		Approve  bool   `json:"approve"`
		Comment  string `json:"comment"`
	}
	decide := func(ctx context.Context, tx pgx.Tx, id accessport.Identity, me string, admin bool, ticket string, b *approval) (itsm.Detail, error) {
		d, e := st.Approve(ctx, tx, id.TenantID, actor(id), me, ticket, b.Revision, admin, b.Approve, b.Comment)
		if e != nil {
			return d, e
		}
		action := "itsm.request_approved"
		if !b.Approve {
			action = "itsm.request_rejected"
		}
		return d, r.Audit.Record(ctx, tx, id.TenantID, id.UserID, action, "ticket", d.ID)
	}
	h["POST /api/v1/itsm/tickets/{ticket_id}/approve"] = route51{"itsm:write", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body approval
		if !readOperationBody(w, req, &body) {
			return
		}
		r.itsmDo(w, req, 200, "itsm:write", func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
			_, e := r.Auth.Authorize(ctx, tx, id.CredentialID, id.TenantID, "itsm:admin")
			admin := e == nil
			me, e := st.MySubject(ctx, tx, id.TenantID, id.UserID)
			if e != nil && !errors.Is(e, itsm.ErrNoSubject) {
				return nil, e // без записи в оргструктуре решает только администратор (иначе NOT_APPROVER)
			}
			return decide(ctx, tx, id, me, admin, req.PathValue("ticket_id"), &body)
		})
	})}
	// Исполнение складской услуги (W3-05): выдача со склада заявителю с актом, связь заявки с движением и переход
	// «исполнено» — одна транзакция; повтор или одновременное исполнение — конфликт, вторая выдача откатывается.
	type fulfill struct {
		Revision     string  `json:"revision"`
		FromLocation string  `json:"from_location"`
		UnitID       string  `json:"unit_id"`
		Quantity     float64 `json:"quantity"`
		Text         string  `json:"text"`
	}
	h["POST /api/v1/itsm/tickets/{ticket_id}/fulfill"] = route51{"itsm:write", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var b fulfill
		if !readOperationBody(w, req, &b) {
			return
		}
		r.itsmDo(w, req, 200, "itsm:write", func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
			if _, e := r.Auth.Authorize(ctx, tx, id.CredentialID, id.TenantID, "warehouse:write"); e != nil {
				return nil, e
			}
			d, e := st.Detail(ctx, tx, id.TenantID, req.PathValue("ticket_id"), true)
			if e != nil {
				return nil, e
			}
			if d.Request == nil || d.Request.WarehouseItem == nil || d.Requester == nil {
				return nil, domain.Invalid // не складская услуга
			}
			if d.State != "in_fulfillment" {
				return nil, domain.Conflict // уже исполнена, ждёт согласования или закрыта
			}
			if d.Revision != b.Revision {
				return nil, domain.Revision
			}
			if (b.UnitID == "") == (b.Quantity == 0) {
				return nil, domain.Invalid // либо экземпляр, либо количество
			}
			if _, e = (warehouse.Store{}).ExpireReservations(ctx, tx, id.TenantID); e != nil {
				return nil, e
			}
			line := warehouse.Line{UnitID: b.UnitID}
			if b.UnitID == "" {
				line = warehouse.Line{ItemID: *d.Request.WarehouseItem, Quantity: b.Quantity}
			}
			m, e := r.warehouseMove(ctx, tx, id, warehouse.Operation{Kind: "issue", Basis: "Заявка " + d.Number + ": " + d.Title,
				FromLocation: b.FromLocation, ToHolder: *d.Requester, Lines: []warehouse.Line{line}})
			if e != nil {
				return nil, e
			}
			for _, l := range m.Lines {
				if l.Item != *d.Request.WarehouseItem {
					return nil, domain.Invalid // выдаётся только позиция, указанная в услуге
				}
			}
			if d, e = st.Fulfilled(ctx, tx, id.TenantID, actor(id), d.ID, b.Revision, m.ID, m.ActNo, b.Text); e != nil {
				return nil, e
			}
			return d, r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "itsm.request_fulfilled", "ticket", d.ID)
		})
	})}
	// Портал заявителя (роль requester, вход по AD): только свои обращения; внутренние комментарии не видны (W3-09).
	portal := func(route string, status int, read bool, newBody func() any, fn func(ctx context.Context, tx pgx.Tx, id accessport.Identity, me string, req *http.Request, body any) (any, error)) {
		h[route] = route51{"itsm:portal", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var body any
			if read {
				if _, ok := queryOnly(w, req); !ok {
					return
				}
			} else {
				body = newBody()
				if !readOperationBody(w, req, body) {
					return
				}
			}
			r.itsmDo(w, req, status, "itsm:portal", func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
				me, e := st.MySubject(ctx, tx, id.TenantID, id.UserID)
				if e != nil {
					return nil, e
				}
				return fn(ctx, tx, id, me, req, body)
			})
		})}
	}
	own := func(ctx context.Context, tx pgx.Tx, tenant, me, ticket string) (itsm.Detail, error) {
		d, e := st.Detail(ctx, tx, tenant, ticket, false)
		if e != nil {
			return d, e
		}
		if d.Requester == nil || *d.Requester != me {
			return itsm.Detail{}, domain.NotFound // чужое обращение не раскрывается
		}
		d.Allowed = []string{}
		switch d.State {
		case "resolved":
			d.Allowed = []string{"closed", "in_progress"} // «решено» / «не решено»
		case "fulfilled":
			d.Allowed = []string{"closed", "in_fulfillment"} // «выполнено» / «не выполнено»
		}
		return d, nil
	}
	portal("GET /api/v1/portal/tickets", 200, true, nil, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, me string, _ *http.Request, _ any) (any, error) {
		items, e := st.List(ctx, tx, id.TenantID, itsm.Filter{Requester: me}, 200)
		return map[string]any{"items": items}, e
	})
	type portalTicket struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Urgency     int    `json:"urgency"`
	}
	portal("POST /api/v1/portal/tickets", 201, false, func() any { return &portalTicket{} }, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, me string, _ *http.Request, body any) (any, error) {
		b := body.(*portalTicket)
		// заявитель сообщает срочность; влияние оценивает оператор при разборе (по умолчанию — низкое)
		d, e := st.Create(ctx, tx, id.TenantID, actor(id), itsm.Input{Kind: "incident", Title: b.Title, Description: b.Description, Impact: 3, Urgency: b.Urgency, Requester: me})
		if e != nil {
			return nil, e
		}
		if e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "itsm.portal_ticket_created", "ticket", d.ID); e != nil {
			return nil, e
		}
		return own(ctx, tx, id.TenantID, me, d.ID)
	})
	portal("GET /api/v1/portal/tickets/{ticket_id}", 200, true, nil, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, me string, req *http.Request, _ any) (any, error) {
		return own(ctx, tx, id.TenantID, me, req.PathValue("ticket_id"))
	})
	type portalComment struct {
		Text string `json:"text"`
	}
	portal("POST /api/v1/portal/tickets/{ticket_id}/comments", 201, false, func() any { return &portalComment{} }, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, me string, req *http.Request, body any) (any, error) {
		if _, e := own(ctx, tx, id.TenantID, me, req.PathValue("ticket_id")); e != nil {
			return nil, e
		}
		if _, e := st.Comment(ctx, tx, id.TenantID, actor(id), req.PathValue("ticket_id"), body.(*portalComment).Text, true); e != nil {
			return nil, e
		}
		return own(ctx, tx, id.TenantID, me, req.PathValue("ticket_id"))
	})
	type confirm struct {
		Revision string `json:"revision"`
		Solved   bool   `json:"solved"`
		Text     string `json:"text"`
	}
	portal("POST /api/v1/portal/tickets/{ticket_id}/confirm", 200, false, func() any { return &confirm{} }, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, me string, req *http.Request, body any) (any, error) {
		b := body.(*confirm)
		d, e := own(ctx, tx, id.TenantID, me, req.PathValue("ticket_id"))
		if e != nil {
			return nil, e
		}
		if len(d.Allowed) != 2 {
			return nil, domain.Conflict // подтверждать нечего: обращение не решено / заявка не исполнена
		}
		to := d.Allowed[0]
		if !b.Solved {
			to = d.Allowed[1] // «не решено» — повторное открытие
		}
		if _, e = st.Transition(ctx, tx, id.TenantID, actor(id), d.ID, b.Revision, to, b.Text); e != nil {
			return nil, e
		}
		if e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "itsm.portal_ticket_"+to, "ticket", d.ID); e != nil {
			return nil, e
		}
		return own(ctx, tx, id.TenantID, me, d.ID)
	})
	portal("GET /api/v1/portal/catalog", 200, true, nil, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, _ string, _ *http.Request, _ any) (any, error) {
		items, e := st.Catalog(ctx, tx, id.TenantID, true)
		for i := range items {
			items[i].Approver, items[i].Team, items[i].WarehouseItem = nil, nil, nil // внутренняя настройка услуги заявителю не нужна
		}
		return map[string]any{"items": items}, e
	})
	type portalRequest struct {
		Item    string            `json:"catalog_item_id"`
		Values  map[string]string `json:"form_values"`
		Urgency int               `json:"urgency"`
	}
	portal("POST /api/v1/portal/requests", 201, false, func() any { return &portalRequest{} }, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, me string, _ *http.Request, body any) (any, error) {
		b := body.(*portalRequest)
		d, e := st.CreateRequest(ctx, tx, id.TenantID, actor(id), me, b.Item, b.Values, b.Urgency)
		if e != nil {
			return nil, e
		}
		if e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "itsm.portal_request_created", "ticket", d.ID); e != nil {
			return nil, e
		}
		return own(ctx, tx, id.TenantID, me, d.ID)
	})
	// Согласующий — сотрудник с портала (руководитель): видит ждущие его решения заявки и решает по ним.
	portal("GET /api/v1/portal/approvals", 200, true, nil, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, me string, _ *http.Request, _ any) (any, error) {
		items, e := st.PendingApprovals(ctx, tx, id.TenantID, me)
		return map[string]any{"items": items}, e
	})
	portal("POST /api/v1/portal/tickets/{ticket_id}/approve", 200, false, func() any { return &approval{} }, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, me string, req *http.Request, body any) (any, error) {
		d, e := decide(ctx, tx, id, me, false, req.PathValue("ticket_id"), body.(*approval))
		if e != nil {
			return nil, e
		}
		d.Events = []itsm.Event{} // согласующему — решение и состояние, не переписка
		d.Allowed = []string{}
		return d, nil
	})
	return h
}
