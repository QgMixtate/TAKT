package app

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/jackc/pgx/v5"

	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/warehouse"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// Склад и жизненный цикл оборудования (волна 2; проект decisions/C41-w2-scope-and-model.md). Права: warehouse:read —
// все, warehouse:write — оператор/администратор, warehouse:admin — администратор (каталог, места, списание).

type warehouseTx func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error)

func (r *Registry) warehouseDo(w http.ResponseWriter, req *http.Request, status int, permission string, write bool, fn warehouseTx) {
	ctx, cancel, id := cmdbContext(req)
	defer cancel()
	iso := pgx.RepeatableRead
	if write {
		iso = pgx.ReadCommitted // конкуренцию решают условные обновления экземпляров и остатков
	}
	tx, e := r.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: iso})
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
	if e != nil {
		cmdbError(w, req, e)
		return
	}
	registryJSONStatus(w, status, out)
}

func limitOf(q url.Values, def, max int) (int, bool) {
	if q.Get("limit") == "" {
		return def, true
	}
	n, e := strconv.Atoi(q.Get("limit"))
	return n, e == nil && n >= 1 && n <= max
}

// Move — складская операция: движение, аудит; списание экземпляра-актива выводит актив из учёта с тем же основанием
// (история, событие, аудит — в той же транзакции, C41.04 W2-07).
func (r *Registry) warehouseMove(ctx context.Context, tx pgx.Tx, id accessport.Identity, op warehouse.Operation) (warehouse.Movement, error) {
	if op.Kind == "write_off" {
		if _, e := r.Auth.Authorize(ctx, tx, id.CredentialID, id.TenantID, "warehouse:admin"); e != nil {
			return warehouse.Movement{}, e
		}
		if e := lockRegistry(ctx, tx, id.TenantID); e != nil {
			return warehouse.Movement{}, e
		}
	}
	m, e := (warehouse.Store{}).Move(ctx, tx, id.TenantID, "user:"+id.UserID, op)
	if e != nil {
		return m, e
	}
	if e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "warehouse."+op.Kind, "movement", m.ID); e != nil {
		return m, e
	}
	if op.Kind != "write_off" {
		return m, nil
	}
	written, e := (warehouse.Store{}).WrittenOffAssets(ctx, tx, id.TenantID, m.ID)
	if e != nil {
		return m, e
	}
	for _, uid := range written {
		if _, e := r.Assets.Get(ctx, tx, id.TenantID, uid); e != nil {
			return m, e
		}
		if ret, e := r.Assets.Retirement(ctx, tx, id.TenantID, uid); e != nil {
			return m, e
		} else if ret != nil {
			continue // уже выведен из учёта
		}
		version, e := r.Assets.Bump(ctx, tx, id.TenantID, uid)
		if e != nil {
			return m, e
		}
		if e = r.Assets.Retire(ctx, tx, id.TenantID, uid, "Списание, акт "+m.ActNo+": "+m.Basis, id.UserID); e != nil {
			return m, e
		}
		if e = r.assetEvent(ctx, tx, id.TenantID, uid, version, "asset.facts_changed.v1", "Assets", "ASSET_RETIRED", id.UserID, identifier.New()); e != nil {
			return m, e
		}
	}
	return m, nil
}

func (r *Registry) warehouseHandlers() map[string]route51 {
	st := warehouse.Store{}
	h := map[string]route51{}
	list := func(perm string, fn func(ctx context.Context, tx pgx.Tx, id accessport.Identity, q url.Values) (any, error), keys ...string) route51 {
		return route51{perm, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			q, ok := queryOnly(w, req, keys...)
			if !ok {
				return
			}
			r.warehouseDo(w, req, 200, perm, false, func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) { return fn(ctx, tx, id, q) })
		})}
	}
	h["GET /api/v1/warehouse/locations"] = list("warehouse:read", func(ctx context.Context, tx pgx.Tx, id accessport.Identity, _ url.Values) (any, error) {
		items, e := st.Locations(ctx, tx, id.TenantID)
		return map[string]any{"items": items}, e
	})
	h["GET /api/v1/warehouse/items"] = list("warehouse:read", func(ctx context.Context, tx pgx.Tx, id accessport.Identity, _ url.Values) (any, error) {
		items, e := st.Items(ctx, tx, id.TenantID)
		return map[string]any{"items": items}, e
	})
	h["GET /api/v1/warehouse/units"] = list("warehouse:read", func(ctx context.Context, tx pgx.Tx, id accessport.Identity, q url.Values) (any, error) {
		n, ok := limitOf(q, 200, 1000)
		if !ok {
			return nil, domain.Invalid
		}
		items, e := st.Units(ctx, tx, id.TenantID, warehouse.UnitFilter{State: q.Get("state"), Holder: q.Get("holder"), Location: q.Get("location"), Asset: q.Get("asset"), Query: q.Get("q")}, n)
		return map[string]any{"items": items}, e
	}, "state", "holder", "location", "asset", "q", "limit")
	h["GET /api/v1/warehouse/stock"] = list("warehouse:read", func(ctx context.Context, tx pgx.Tx, id accessport.Identity, q url.Values) (any, error) {
		items, e := st.Stock(ctx, tx, id.TenantID, q.Get("location"))
		return map[string]any{"items": items}, e
	}, "location")
	h["GET /api/v1/warehouse/movements"] = list("warehouse:read", func(ctx context.Context, tx pgx.Tx, id accessport.Identity, q url.Values) (any, error) {
		n, ok := limitOf(q, 100, 500)
		if !ok {
			return nil, domain.Invalid
		}
		items, e := st.Movements(ctx, tx, id.TenantID, warehouse.MovementFilter{Unit: q.Get("unit"), Holder: q.Get("holder"), Location: q.Get("location"), Asset: q.Get("asset")}, n)
		return map[string]any{"items": items}, e
	}, "unit", "holder", "location", "asset", "limit")
	h["GET /api/v1/warehouse/movements/{movement_id}"] = route51{"warehouse:read", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		r.warehouseDo(w, req, 200, "warehouse:read", false, func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
			return st.Movement(ctx, tx, id.TenantID, req.PathValue("movement_id"))
		})
	})}
	h["GET /api/v1/warehouse/verify"] = list("warehouse:admin", func(ctx context.Context, tx pgx.Tx, id accessport.Identity, _ url.Values) (any, error) {
		items, e := st.VerifyStock(ctx, tx, id.TenantID)
		return map[string]any{"discrepancies": items}, e
	})
	write := func(perm string, status int, fn func(ctx context.Context, tx pgx.Tx, id accessport.Identity, req *http.Request) (any, error)) route51 {
		return route51{perm, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			r.warehouseDo(w, req, status, perm, true, func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) { return fn(ctx, tx, id, req) })
		})}
	}
	h["POST /api/v1/warehouse/locations"] = route51{"warehouse:admin", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body warehouse.Location
		if !readOperationBody(w, req, &body) {
			return
		}
		write("warehouse:admin", 201, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, _ *http.Request) (any, error) {
			l, e := st.CreateLocation(ctx, tx, id.TenantID, body)
			if e == nil {
				e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "warehouse.location_created", "location", l.ID)
			}
			return l, e
		}).handler.ServeHTTP(w, req)
	})}
	h["POST /api/v1/warehouse/items"] = route51{"warehouse:admin", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body warehouse.Item
		if !readOperationBody(w, req, &body) {
			return
		}
		write("warehouse:admin", 201, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, _ *http.Request) (any, error) {
			it, e := st.CreateItem(ctx, tx, id.TenantID, body)
			if e == nil {
				e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "warehouse.item_created", "item", it.ID)
			}
			return it, e
		}).handler.ServeHTTP(w, req)
	})}
	h["POST /api/v1/warehouse/movements"] = route51{"warehouse:write", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body warehouse.Operation
		if !readOperationBody(w, req, &body) {
			return
		}
		write("warehouse:write", 201, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, _ *http.Request) (any, error) {
			return r.warehouseMove(ctx, tx, id, body)
		}).handler.ServeHTTP(w, req)
	})}
	return h
}
