package app

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/cmdb"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
)

// C57.01 — снимки платформ (contracts/c57-platform.schema.json): приём от collector по mTLS с подписью его ключом;
// чтение для Web — экземпляры платформ, их объекты и объекты, сопоставленные с активом (карточка хоста).

// platformMachine — POST /api/v1/machine/platform-snapshots.
func (r *Registry) platformMachine(w http.ResponseWriter, req *http.Request) {
	ctx, cancel := context.WithTimeout(req.Context(), 60*time.Second)
	defer cancel()
	if req.TLS == nil || len(req.TLS.VerifiedChains) == 0 || len(req.TLS.PeerCertificates) == 0 {
		access.APIError(w, 401, "AUTHENTICATION_REQUIRED")
		return
	}
	if req.URL.RawQuery != "" {
		access.APIError(w, 400, "INVALID_QUERY")
		return
	}
	if kind, _, e := mime.ParseMediaType(req.Header.Get("Content-Type")); e != nil || kind != "application/json" {
		access.APIError(w, 400, "INVALID_JSON")
		return
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, req.Body, 32<<20))
	if e != nil {
		access.APIError(w, 413, "PAYLOAD_TOO_LARGE")
		return
	}
	if r.Machine == nil || r.Machine.Sources == nil || r.Pool == nil {
		access.APIError(w, 503, "TEMPORARILY_UNAVAILABLE")
		return
	}
	out, e := r.SubmitPlatformSnapshot(ctx, pki.Fingerprint(req.TLS.PeerCertificates[0]), raw)
	if e != nil {
		switch {
		case errors.Is(e, domain.Invalid):
			access.APIError(w, 400, "SCHEMA_INVALID")
		case errors.Is(e, domain.Unauthorized):
			access.APIError(w, 403, "SOURCE_NOT_AUTHORIZED")
		default:
			access.APIError(w, 503, "TEMPORARILY_UNAVAILABLE")
		}
		return
	}
	registryJSON(w, out)
}

// SubmitPlatformSnapshot — проверка подписи collector, строгий разбор и запись снимка одной транзакцией.
func (r *Registry) SubmitPlatformSnapshot(ctx context.Context, fp string, raw []byte) (cmdb.PlatformSnapshotResult, error) {
	var out cmdb.PlatformSnapshotResult
	tx, e := r.Pool.Begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	payload, _, e := r.Machine.Sources.VerifyPlatformSnapshot(ctx, tx, fp, raw)
	if e != nil {
		return out, e
	}
	var s cmdb.PlatformSnapshot
	if e = sources.Strict(payload, &s); e != nil {
		return out, e
	}
	if out, e = r.CMDB.SavePlatformSnapshot(ctx, tx, s); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

func (r *Registry) platformHandlers(h map[string]rsmRoute) {
	read := func(fn func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity)) rsmRoute {
		return rsmRoute{"assets:read", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx, cancel, id := cmdbContext(req)
			defer cancel()
			fn(w, req, ctx, id)
		})}
	}
	h["GET /api/v1/platforms"] = read(func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		tx, e := r.readTx(ctx, id)
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		defer tx.Rollback(ctx)
		items, e := r.CMDB.PlatformInstances(ctx, tx, id.TenantID)
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, map[string]any{"items": items})
	})
	h["GET /api/v1/platforms/{instance_id}/objects"] = read(func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity) {
		q, ok := queryOnly(w, req, "kind", "q", "unmatched", "offset", "limit")
		if !ok {
			return
		}
		limit, ok := pageLimit(w, q, 100, 500)
		if !ok {
			return
		}
		offset := 0
		if v := q.Get("offset"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > 1000000 {
				access.APIError(w, 400, "INVALID_QUERY")
				return
			}
			offset = n
		}
		tx, e := r.readTx(ctx, id)
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		defer tx.Rollback(ctx)
		items, total, e := r.CMDB.PlatformObjects(ctx, tx, id.TenantID, req.PathValue("instance_id"), q.Get("kind"), q.Get("q"), q.Get("unmatched") == "true", offset, limit)
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, map[string]any{"items": items, "total": total})
	})
	h["GET /api/v1/assets/{asset_uid}/platform"] = read(func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		tx, e := r.readTx(ctx, id)
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		defer tx.Rollback(ctx)
		uid := req.PathValue("asset_uid")
		items, e := r.CMDB.AssetPlatform(ctx, tx, id.TenantID, uid)
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, map[string]any{"asset_uid": uid, "items": items})
	})
}
