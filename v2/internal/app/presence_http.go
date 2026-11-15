package app

import (
	"context"
	"net/http"

	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// AssetPresence — присутствие актива в сети по обследованиям подсетей (C21.02, контракт c21-presence). Отдельно от
// свежести данных и пульса агента: актив может быть «на месте» с устаревшими данными и наоборот.
type AssetPresence struct {
	Asset     string                 `json:"asset_uid"`
	MissAfter int                    `json:"miss_after"`
	State     string                 `json:"state"` // present | missing | unknown (нет обследований с адресами актива)
	Items     []sources.HostPresence `json:"items"`
}

func (r *Registry) AssetPresence(ctx context.Context, id accessport.Identity, uid string) (AssetPresence, error) {
	out := AssetPresence{Asset: uid, MissAfter: sources.DiscoveryMissAfter, State: "unknown", Items: []sources.HostPresence{}}
	if !identifier.Valid(uid) {
		return out, domain.NotFound
	}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if _, e = r.Assets.Get(ctx, tx, id.TenantID, uid); e != nil {
		return out, e
	}
	var ips []string
	if e = tx.QueryRow(ctx, `SELECT COALESCE(array_agg(DISTINCT ip),'{}') FROM (
SELECT jsonb_array_elements(value::jsonb)->>'ip' AS ip FROM inventory.current_facts WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='network' AND fact_key LIKE '%.addresses'
UNION ALL SELECT jsonb_array_elements(value)->>'ip' FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='network' AND field_name='addresses' AND jsonb_typeof(value)='array') x WHERE ip IS NOT NULL`, id.TenantID, uid).Scan(&ips); e != nil {
		return out, e
	}
	if out.Items, e = (sources.Store{}).DiscoveryPresence(ctx, tx, id.TenantID, ips); e != nil {
		return out, e
	}
	// актив на месте, если хотя бы один его адрес найден; пропал — только если пропали все найденные ранее адреса
	for _, p := range out.Items {
		if p.State == "present" {
			out.State = "present"
			break
		}
		out.State = "missing"
	}
	return out, tx.Commit(ctx)
}

func (r *Registry) presenceHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		out, e := r.AssetPresence(ctx, id, req.PathValue("asset_uid"))
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, out)
	})
}
