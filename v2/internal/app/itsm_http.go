package app

import (
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/itsm"
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
	switch {
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
	}
	post("POST /api/v1/itsm/tickets/{ticket_id}/transition", 200, func() any { return &transition{} }, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, req *http.Request, body any) (itsm.Detail, string, error) {
		b := body.(*transition)
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
	return h
}
