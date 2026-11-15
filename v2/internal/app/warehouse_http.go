package app

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/jackc/pgx/v5"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
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
	if write || req.URL.Path == "/api/v1/warehouse/reservations" {
		// просроченные резервы снимаются до операции: свободный остаток и экземпляры актуальны
		if _, e = (warehouse.Store{}).ExpireReservations(ctx, tx, id.TenantID); e != nil {
			registryError(w, e)
			return
		}
	}
	out, e := fn(ctx, tx, id)
	if e == nil {
		e = tx.Commit(ctx)
	}
	var incompatible *warehouse.IncompatibleError
	switch {
	case errors.As(e, &incompatible):
		access.APIError(w, 409, "INCOMPATIBLE_COMPONENT") // установить можно только с пометкой «под ответственность»
		return
	case errors.Is(e, warehouse.ErrInventoryOpen):
		access.APIError(w, 409, "LOCATION_UNDER_INVENTORY")
		return
	case e != nil:
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
	h["POST /api/v1/warehouse/movements/{movement_id}/reverse"] = route51{"warehouse:write", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			Basis string `json:"basis"`
		}
		if !readOperationBody(w, req, &body) {
			return
		}
		write("warehouse:write", 201, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, _ *http.Request) (any, error) {
			m, e := st.Reverse(ctx, tx, id.TenantID, "user:"+id.UserID, req.PathValue("movement_id"), body.Basis)
			if e == nil {
				e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "warehouse.reverse", "movement", m.ID)
			}
			return m, e
		}).handler.ServeHTTP(w, req)
	})}
	h["GET /api/v1/warehouse/reservations"] = list("warehouse:read", func(ctx context.Context, tx pgx.Tx, id accessport.Identity, _ url.Values) (any, error) {
		items, e := st.Reservations(ctx, tx, id.TenantID, 500)
		return map[string]any{"items": items}, e
	})
	h["POST /api/v1/warehouse/reservations"] = route51{"warehouse:write", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body warehouse.ReservationInput
		if !readOperationBody(w, req, &body) {
			return
		}
		write("warehouse:write", 201, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, _ *http.Request) (any, error) {
			res, e := st.Reserve(ctx, tx, id.TenantID, "user:"+id.UserID, body)
			if e == nil {
				e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "warehouse.reserved", "reservation", res.ID)
			}
			return res, e
		}).handler.ServeHTTP(w, req)
	})}
	h["POST /api/v1/warehouse/reservations/{reservation_id}/cancel"] = route51{"warehouse:write", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body struct{}
		if !readOperationBody(w, req, &body) {
			return
		}
		write("warehouse:write", 200, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, _ *http.Request) (any, error) {
			res, e := st.CancelReservation(ctx, tx, id.TenantID, req.PathValue("reservation_id"))
			if e == nil {
				e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "warehouse.reservation_cancelled", "reservation", res.ID)
			}
			return res, e
		}).handler.ServeHTTP(w, req)
	})}
	h["PUT /api/v1/warehouse/items/{item_id}/compatibility"] = route51{"warehouse:admin", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			Models []string `json:"compatible_models"`
		}
		if !readOperationBody(w, req, &body) {
			return
		}
		write("warehouse:admin", 200, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, _ *http.Request) (any, error) {
			item := req.PathValue("item_id")
			if e := st.SetCompatibility(ctx, tx, id.TenantID, item, body.Models); e != nil {
				return nil, e
			}
			if e := r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "warehouse.item_compatibility_set", "item", item); e != nil {
				return nil, e
			}
			items, e := st.Items(ctx, tx, id.TenantID)
			for _, it := range items {
				if it.ID == item {
					return it, e
				}
			}
			return nil, e
		}).handler.ServeHTTP(w, req)
	})}
	h["GET /api/v1/warehouse/compatibility"] = list("warehouse:read", func(ctx context.Context, tx pgx.Tx, id accessport.Identity, q url.Values) (any, error) {
		if !identifier.Valid(q.Get("item")) || !identifier.Valid(q.Get("asset")) {
			return nil, domain.Invalid
		}
		fits, model, e := st.Compatible(ctx, tx, id.TenantID, q.Get("item"), q.Get("asset"))
		return map[string]any{"compatible": fits, "asset_model": model}, e
	}, "item", "asset")
	h["GET /api/v1/warehouse/inventories"] = list("warehouse:read", func(ctx context.Context, tx pgx.Tx, id accessport.Identity, _ url.Values) (any, error) {
		items, e := st.Inventories(ctx, tx, id.TenantID, 100)
		return map[string]any{"items": items}, e
	})
	h["GET /api/v1/warehouse/inventories/{inventory_id}"] = route51{"warehouse:read", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		r.warehouseDo(w, req, 200, "warehouse:read", false, func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
			return st.InventoryDetail(ctx, tx, id.TenantID, req.PathValue("inventory_id"))
		})
	})}
	h["POST /api/v1/warehouse/inventories"] = route51{"warehouse:write", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			Location string `json:"location_id"`
			Basis    string `json:"basis"`
		}
		if !readOperationBody(w, req, &body) {
			return
		}
		write("warehouse:write", 201, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, _ *http.Request) (any, error) {
			d, e := st.StartInventory(ctx, tx, id.TenantID, "user:"+id.UserID, body.Location, body.Basis)
			if e == nil {
				e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "warehouse.inventory_started", "inventory", d.ID)
			}
			return d, e
		}).handler.ServeHTTP(w, req)
	})}
	h["PUT /api/v1/warehouse/inventories/{inventory_id}/count"] = route51{"warehouse:write", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body warehouse.Count
		if !readOperationBody(w, req, &body) {
			return
		}
		write("warehouse:write", 200, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, _ *http.Request) (any, error) {
			return st.SetCount(ctx, tx, id.TenantID, req.PathValue("inventory_id"), body)
		}).handler.ServeHTTP(w, req)
	})}
	for _, verb := range []string{"close", "cancel"} {
		perm := map[string]string{"close": "warehouse:admin", "cancel": "warehouse:write"}[verb]
		h["POST /api/v1/warehouse/inventories/{inventory_id}/"+verb] = route51{perm, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var body struct{}
			if !readOperationBody(w, req, &body) {
				return
			}
			write(perm, 200, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, _ *http.Request) (any, error) {
				var d warehouse.InventoryDetail
				var e error
				if verb == "close" {
					d, e = st.CloseInventory(ctx, tx, id.TenantID, "user:"+id.UserID, req.PathValue("inventory_id"))
				} else {
					d, e = st.CancelInventory(ctx, tx, id.TenantID, "user:"+id.UserID, req.PathValue("inventory_id"))
				}
				if e == nil {
					e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, map[string]string{"close": "warehouse.inventory_closed", "cancel": "warehouse.inventory_cancelled"}[verb], "inventory", d.ID)
				}
				return d, e
			}).handler.ServeHTTP(w, req)
		})}
	}
	return h
}
