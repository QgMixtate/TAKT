package app

// C53.07 — «Источники» по макету: колонка «Что / сколько» и панель выбранного источника. Сводка по источникам
// страницы: сколько хостов видно через источник, цели сбора collector (SSH/WinRM/SNMP, с ошибкой, отключены),
// последняя ошибка, а для источника цели сбора — кто и по какому адресу его собирает. Только чтение.

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

type SourceTargetCounts struct {
	SSH      int `json:"ssh"`
	WinRM    int `json:"winrm"`
	SNMP     int `json:"snmp"`
	Errors   int `json:"errors"`
	Disabled int `json:"disabled"`
}

type SourceCollectedBy struct {
	CollectorID string `json:"collector_id"`
	Kind        string `json:"kind"`
	Address     string `json:"address"`
}

type SourceOverview struct {
	SourceID        string             `json:"source_id"`
	Hosts           int                `json:"hosts"`
	Targets         SourceTargetCounts `json:"targets"`
	LastError       *string            `json:"last_error"`
	LastErrorTarget *string            `json:"last_error_target"`
	LastCollectedAt *time.Time         `json:"last_collected_at"`
	CollectedBy     *SourceCollectedBy `json:"collected_by"`
}

type SourceOverviewList struct {
	Items []SourceOverview `json:"items"`
}

const sourceOverviewMax = 100

func (r *Registry) SourcesOverview(ctx context.Context, id accessport.Identity, ids []string) (SourceOverviewList, error) {
	out := SourceOverviewList{Items: []SourceOverview{}}
	if len(ids) == 0 {
		return out, nil
	}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	// хосты: записи самого источника и, для collector, записи источников его целей сбора; выведенные из учёта — не считаются
	rows, e := tx.Query(ctx, `WITH s AS (SELECT src.source_id FROM sources.sources src WHERE src.tenant_id=$1 AND src.source_id=ANY($2::uuid[])),
via AS (SELECT s.source_id AS owner, s.source_id AS rec FROM s
 UNION SELECT t.collector_id, t.agent_source_id FROM sources.remote_targets t JOIN s ON s.source_id=t.collector_id WHERE t.tenant_id=$1 AND t.agent_source_id IS NOT NULL)
SELECT s.source_id::text,
 (SELECT count(DISTINCT r.asset_uid) FROM via v JOIN assets.source_records r ON r.tenant_id=$1 AND r.source_id=v.rec JOIN assets.assets a ON a.tenant_id=r.tenant_id AND a.asset_uid=r.asset_uid AND a.retired_at IS NULL WHERE v.owner=s.source_id),
 (SELECT count(*) FILTER (WHERE kind='ssh') FROM sources.remote_targets WHERE tenant_id=$1 AND collector_id=s.source_id),
 (SELECT count(*) FILTER (WHERE kind='winrm') FROM sources.remote_targets WHERE tenant_id=$1 AND collector_id=s.source_id),
 (SELECT count(*) FILTER (WHERE kind='snmp') FROM sources.remote_targets WHERE tenant_id=$1 AND collector_id=s.source_id),
 (SELECT count(*) FILTER (WHERE last_error IS NOT NULL AND state<>'disabled') FROM sources.remote_targets WHERE tenant_id=$1 AND collector_id=s.source_id),
 (SELECT count(*) FILTER (WHERE state='disabled') FROM sources.remote_targets WHERE tenant_id=$1 AND collector_id=s.source_id),
 e.last_error, e.target, (SELECT max(last_collected_at) FROM sources.remote_targets WHERE tenant_id=$1 AND (collector_id=s.source_id OR agent_source_id=s.source_id)),
 b.collector_id::text, b.kind, host(b.address)
FROM s
LEFT JOIN LATERAL (SELECT t.last_error, upper(t.kind)||' '||host(t.address) AS target FROM sources.remote_targets t WHERE t.tenant_id=$1 AND (t.collector_id=s.source_id OR t.agent_source_id=s.source_id) AND t.last_error IS NOT NULL AND t.state<>'disabled' ORDER BY t.last_collected_at DESC NULLS LAST LIMIT 1) e ON true
LEFT JOIN LATERAL (SELECT t.collector_id, t.kind, t.address FROM sources.remote_targets t WHERE t.tenant_id=$1 AND t.agent_source_id=s.source_id ORDER BY t.created_at LIMIT 1) b ON true`, id.TenantID, ids)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		var o SourceOverview
		var cid, kind, addr *string
		if e = rows.Scan(&o.SourceID, &o.Hosts, &o.Targets.SSH, &o.Targets.WinRM, &o.Targets.SNMP, &o.Targets.Errors, &o.Targets.Disabled, &o.LastError, &o.LastErrorTarget, &o.LastCollectedAt, &cid, &kind, &addr); e != nil {
			return out, e
		}
		if o.LastCollectedAt != nil {
			t := o.LastCollectedAt.UTC()
			o.LastCollectedAt = &t
		}
		if cid != nil && kind != nil && addr != nil {
			o.CollectedBy = &SourceCollectedBy{CollectorID: *cid, Kind: *kind, Address: *addr}
		}
		out.Items = append(out.Items, o)
	}
	return out, rows.Err()
}

func (r *Registry) sourceOverviewHandlers(h map[string]rsmRoute) {
	h["GET /api/v1/sources/overview"] = rsmRoute{"sources:read", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q, err := url.ParseQuery(req.URL.RawQuery)
		if err != nil || len(q) != 1 || len(q["ids"]) != 1 {
			access.APIError(w, 400, "INVALID_QUERY")
			return
		}
		ids := strings.Split(q["ids"][0], ",")
		if len(ids) > sourceOverviewMax {
			access.APIError(w, 400, "INVALID_QUERY")
			return
		}
		for _, v := range ids {
			if !identifier.Valid(v) {
				access.APIError(w, 400, "INVALID_QUERY")
				return
			}
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		out, e := r.SourcesOverview(ctx, id, ids)
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, out)
	})}
}
