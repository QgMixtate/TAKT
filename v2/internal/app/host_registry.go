package app

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/cmdb"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/telemetry"
	"github.com/jackc/pgx/v5"
)

// C53.04 — проекция плотного реестра хостов (cmdb.host_registry). Полный пересчёт — раз в 5 минут для каждого
// арендатора; точечное обновление — после приёма наблюдения по активу. Данные: активы и бизнес-поля, инвентаризация
// (имя, ОС, разделы, свежесть), IP, площадка и сегмент, ответственный (и его команда, резерв площадки), основная
// привязка РСМ, источники. Наблюдаемый класс пересчитывается, только если изменилось время инвентаризации.

const hostRegistryBatch = 1000

func osFamily(os string) string {
	l := strings.ToLower(os)
	switch {
	case l == "":
		return "unknown"
	case strings.Contains(l, "windows"):
		return "windows"
	case strings.Contains(l, "mac") || strings.Contains(l, "darwin"):
		return "macos"
	case strings.Contains(l, "ios") || strings.Contains(l, "routeros") || strings.Contains(l, "junos") || strings.Contains(l, "fortios") || strings.Contains(l, "cisco") || strings.Contains(l, "huawei") || strings.Contains(l, "mikrotik"):
		return "network"
	case strings.Contains(l, "linux") || strings.Contains(l, "ubuntu") || strings.Contains(l, "debian") || strings.Contains(l, "centos") || strings.Contains(l, "rhel") || strings.Contains(l, "red hat") || strings.Contains(l, "astra") || strings.Contains(l, "alma") || strings.Contains(l, "rocky") || strings.Contains(l, "suse") || strings.Contains(l, "alt ") || strings.Contains(l, "red os") || strings.Contains(l, "fedora"):
		return "linux"
	}
	return "other"
}

// hostRegistryRows — строки проекции для пачки активов; второй результат — активы, которых в реестре быть не должно.
func (r *Registry) hostRegistryRows(ctx context.Context, tx pgx.Tx, tenant string, uids []string, now time.Time) ([]cmdb.HostRegistryRow, []string, error) {
	list, _, e := r.Assets.GetMany(ctx, tx, tenant, uids)
	if e != nil {
		return nil, nil, e
	}
	ptrs := make([]*contracts.Asset, len(list))
	for i := range list {
		ptrs[i] = &list[i]
	}
	if e = r.Inventory.EnrichMany(ctx, tx, ptrs); e != nil {
		return nil, nil, e
	}
	owners, e := r.Owners.AccountableMany(ctx, tx, tenant, uids)
	if e != nil {
		return nil, nil, e
	}
	ips, e := rsmIPs(ctx, tx, tenant, uids)
	if e != nil {
		return nil, nil, e
	}
	names, e := rsmNames(ctx, tx, tenant, uids) // имя как в карточке (профили 1.0 и 1.2)
	if e != nil {
		return nil, nil, e
	}
	type place struct {
		site, segment string
		created       time.Time
		retired       bool
	}
	places := map[string]place{}
	rows, e := tx.Query(ctx, `SELECT a.asset_uid::text,COALESCE(st.name,''),COALESCE(ns.namespace,''),a.created_at,a.retired_at IS NOT NULL OR a.merged_into IS NOT NULL
FROM assets.assets a LEFT JOIN scope.sites st ON st.tenant_id=a.tenant_id AND st.site_id=a.site_id LEFT JOIN scope.network_scopes ns ON ns.tenant_id=a.tenant_id AND ns.scope_id=a.scope_id
WHERE a.tenant_id=$1 AND a.asset_uid=ANY($2::uuid[])`, tenant, uids)
	if e != nil {
		return nil, nil, e
	}
	for rows.Next() {
		var u string
		var p place
		if e = rows.Scan(&u, &p.site, &p.segment, &p.created, &p.retired); e != nil {
			rows.Close()
			return nil, nil, e
		}
		places[u] = p
	}
	rows.Close()
	type subject struct {
		name, team string
		fallback   bool
	}
	subjects := map[string]subject{}
	rows, e = tx.Query(ctx, `SELECT s.subject_id::text,s.name,CASE WHEN s.kind='team' THEN s.name ELSE COALESCE((SELECT t.name FROM responsibility.team_members m JOIN responsibility.subjects t ON t.tenant_id=m.tenant_id AND t.subject_id=m.team_id
WHERE m.tenant_id=s.tenant_id AND m.person_id=s.subject_id AND m.valid_to IS NULL ORDER BY t.name LIMIT 1),'') END,
EXISTS(SELECT 1 FROM scope.sites x WHERE x.tenant_id=s.tenant_id AND x.fallback_subject_id=s.subject_id)
FROM responsibility.subjects s WHERE s.tenant_id=$1 AND s.subject_id IN (SELECT a.subject_id FROM responsibility.responsibility_assignments a WHERE a.tenant_id=$1 AND a.asset_uid=ANY($2::uuid[]) AND a.role='accountable' AND a.valid_to IS NULL)`, tenant, uids)
	if e != nil {
		return nil, nil, e
	}
	for rows.Next() {
		var id string
		var s subject
		if e = rows.Scan(&id, &s.name, &s.team, &s.fallback); e != nil {
			rows.Close()
			return nil, nil, e
		}
		subjects[id] = s
	}
	rows.Close()
	type binding struct{ system, systemName, component string }
	bindings := map[string]binding{}
	rows, e = tx.Query(ctx, `SELECT DISTINCT ON (b.asset_uid) b.asset_uid::text,s.service_uid::text,s.name,c.name FROM cmdb.bindings b
JOIN cmdb.components c ON c.tenant_id=b.tenant_id AND c.component_id=b.component_id AND c.retired_at IS NULL
JOIN cmdb.environments e ON e.tenant_id=c.tenant_id AND e.environment_id=c.environment_id AND e.retired_at IS NULL
JOIN cmdb.services s ON s.tenant_id=e.tenant_id AND s.service_uid=e.service_uid AND s.retired_at IS NULL
WHERE b.tenant_id=$1 AND b.asset_uid=ANY($2::uuid[]) AND b.valid_to IS NULL AND b.status='active' ORDER BY b.asset_uid,b.is_primary DESC,b.valid_from`, tenant, uids)
	if e != nil {
		return nil, nil, e
	}
	for rows.Next() {
		var u string
		var b binding
		if e = rows.Scan(&u, &b.system, &b.systemName, &b.component); e != nil {
			rows.Close()
			return nil, nil, e
		}
		bindings[u] = b
	}
	rows.Close()
	sources := map[string][]string{}
	rows, e = tx.Query(ctx, `SELECT DISTINCT r.asset_uid::text,CASE WHEN s.source_kind='agent' THEN COALESCE((SELECT g.acquisition FROM sources.agents g WHERE g.tenant_id=s.tenant_id AND g.source_id=s.source_id LIMIT 1),'agent') ELSE s.source_kind END
FROM assets.source_records r JOIN sources.sources s ON s.tenant_id=r.tenant_id AND s.source_id=r.source_id WHERE r.tenant_id=$1 AND r.asset_uid=ANY($2::uuid[]) ORDER BY 1,2`, tenant, uids)
	if e != nil {
		return nil, nil, e
	}
	for rows.Next() {
		var u, k string
		if e = rows.Scan(&u, &k); e != nil {
			rows.Close()
			return nil, nil, e
		}
		sources[u] = append(sources[u], k)
	}
	rows.Close()
	// №70: разделы профиля 1.2 (portable, SSH/WinRM, run12) — как в карточке: из 12 разделов собраны те, у кого
	// последняя попытка дала данные; у активов только с 1.0 разделы берутся из a.Sections.
	// «не поддерживается» и «не запрашивался» — не недостача (ISSUES №74): в знаменателе только ожидаемые разделы
	sections12OK, sections12Total := map[string]int{}, map[string]int{}
	rows, e = tx.Query(ctx, `SELECT asset_uid::text,count(*) FILTER (WHERE last_status='partial'),count(*) FILTER (WHERE last_status NOT IN ('unsupported','not_requested')) FROM inventory.record_section_state12 WHERE tenant_id=$1 AND asset_uid=ANY($2::uuid[]) GROUP BY asset_uid`, tenant, uids)
	if e != nil {
		return nil, nil, e
	}
	for rows.Next() {
		var u string
		var n, total int
		if e = rows.Scan(&u, &n, &total); e != nil {
			rows.Close()
			return nil, nil, e
		}
		sections12OK[u], sections12Total[u] = n, total
	}
	rows.Close()
	previous, e := r.CMDB.HostRegistryClasses(ctx, tx, tenant, uids)
	if e != nil {
		return nil, nil, e
	}
	out := make([]cmdb.HostRegistryRow, 0, len(list))
	seen := map[string]bool{}
	for _, a := range list {
		p, ok := places[a.UID]
		if !ok || p.retired {
			continue
		}
		seen[a.UID] = true
		name := ""
		if a.Business.DisplayName != nil && *a.Business.DisplayName != "" {
			name = *a.Business.DisplayName
		} else if names[a.UID] != "" {
			name = names[a.UID]
		} else if a.Hostname != nil {
			name = *a.Hostname
		}
		if name == "" {
			name = a.UID[:8]
		}
		row := cmdb.HostRegistryRow{AssetUID: a.UID, Name: name, IP: ips[a.UID], SiteID: a.SiteID, SiteName: p.site, Segment: p.segment, Freshness: a.Freshness,
			LastInventory: a.LastInventory, CreatedAt: p.created, ComputedAt: now, Sources: sources[a.UID], Class: "unknown"}
		if row.Sources == nil {
			row.Sources = []string{}
		}
		if a.OS != nil {
			row.OS = *a.OS
		}
		row.OSFamily = osFamily(row.OS)
		if row.Freshness != "fresh" && row.Freshness != "stale" {
			row.Freshness = "unknown"
			// №79: как в карточке и РСМ — сбор старше суток устарел, даже если источник не подтверждает свежесть (portable)
			if a.LastInventory != nil && time.Since(*a.LastInventory) > 24*time.Hour {
				row.Freshness = "stale"
			}
		}
		if owner, ok := owners[a.UID]; ok {
			o := owner
			row.AccountableID = &o
			s := subjects[owner]
			row.Accountable, row.Team, row.SiteFallback = s.name, s.team, s.fallback
		}
		if b, ok := bindings[a.UID]; ok {
			sys := b.system
			row.SystemUID, row.System, row.Component = &sys, b.systemName, b.component
		}
		for _, s := range a.Sections {
			if s.Status == "unsupported" || s.Status == "not_requested" {
				continue
			}
			row.SectionsTotal++
			if s.Status == "ok" {
				row.SectionsOK++
			}
		}
		if n, ok := sections12OK[a.UID]; ok && row.SectionsTotal == 0 {
			row.SectionsTotal, row.SectionsOK = sections12Total[a.UID], n
		}
		// класс: ручной важнее наблюдаемого; наблюдаемый — заново только при новой инвентаризации
		manual, _, e := r.Assets.ManualClass(ctx, tx, tenant, a.UID)
		if e != nil {
			return nil, nil, e
		}
		if manual != nil {
			row.Class = *manual
		} else if prev, ok := previous[a.UID]; ok && prev.Class != "" && ((prev.LastInventory == nil && a.LastInventory == nil) || (prev.LastInventory != nil && a.LastInventory != nil && prev.LastInventory.Equal(*a.LastInventory))) {
			row.Class = prev.Class
		} else if observed, _, e := r.Inventory.ObservedClass(ctx, tx, tenant, a.UID); e != nil {
			return nil, nil, e
		} else if observed != "" {
			row.Class = observed
		}
		out = append(out, row)
	}
	gone := []string{}
	for _, u := range uids {
		if !seen[u] {
			gone = append(gone, u)
		}
	}
	return out, gone, nil
}

// RecomputeHostRegistry — полный пересчёт проекции арендатора пачками; в конце убираются строки, которых больше нет.
func (r *Registry) RecomputeHostRegistry(ctx context.Context, tenant string) (int, error) {
	start := time.Now().UTC()
	after, total := "", 0
	for {
		read, e := r.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if e != nil {
			return total, e
		}
		uids, e := r.Assets.IDs(ctx, read, tenant, after, hostRegistryBatch)
		if e != nil || len(uids) == 0 {
			read.Rollback(ctx)
			if e != nil {
				return total, e
			}
			break
		}
		rows, _, e := r.hostRegistryRows(ctx, read, tenant, uids, start)
		read.Rollback(ctx)
		if e != nil {
			return total, e
		}
		if e = r.saveHostRows(ctx, tenant, rows, nil); e != nil {
			return total, e
		}
		total += len(rows)
		after = uids[len(uids)-1]
	}
	tx, e := r.Pool.Begin(ctx)
	if e != nil {
		return total, e
	}
	defer tx.Rollback(ctx)
	if e = r.CMDB.PruneHostRegistry(ctx, tx, tenant, start); e != nil {
		return total, e
	}
	return total, tx.Commit(ctx)
}

func (r *Registry) saveHostRows(ctx context.Context, tenant string, rows []cmdb.HostRegistryRow, gone []string) error {
	tx, e := r.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if e = r.CMDB.SaveHostRegistry(ctx, tx, tenant, rows); e != nil {
		return e
	}
	if e = r.CMDB.RemoveHostRegistry(ctx, tx, tenant, gone); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

// RefreshHostRegistry — точечное обновление строк (после приёма наблюдения, правки карточки, слияния).
func (r *Registry) RefreshHostRegistry(ctx context.Context, tenant string, uids []string) error {
	if len(uids) == 0 {
		return nil
	}
	read, e := r.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if e != nil {
		return e
	}
	rows, gone, e := r.hostRegistryRows(ctx, read, tenant, uids, time.Now().UTC())
	read.Rollback(ctx)
	if e != nil {
		return e
	}
	return r.saveHostRows(ctx, tenant, rows, gone)
}

func (r *Registry) refreshHostAfterIngest(ctx context.Context, tenant, uid string) {
	if e := r.RefreshHostRegistry(ctx, tenant, []string{uid}); e != nil {
		telemetry.Log(os.Stderr, "center", "host_registry_refresh_failed")
	}
}

// HostRegistryMaintain — фоновый пересчёт проекции реестра хостов: сразу после старта и затем раз в 5 минут.
func (r *Registry) HostRegistryMaintain(ctx context.Context, log func(string)) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for first := true; ; first = false {
		if !first {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
		task, done := context.WithTimeout(ctx, 4*time.Minute)
		var tenants []string
		rows, e := r.Pool.Query(task, "SELECT DISTINCT tenant_id::text FROM assets.assets")
		if e == nil {
			for rows.Next() {
				var x string
				if e = rows.Scan(&x); e != nil {
					break
				}
				tenants = append(tenants, x)
			}
			rows.Close()
		}
		if e != nil {
			log("host registry: tenants unavailable: " + e.Error())
		}
		for _, tenant := range tenants {
			if _, e := r.RecomputeHostRegistry(task, tenant); e != nil {
				log("host registry recompute failed: " + e.Error())
			}
		}
		done()
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// refreshHostAfter — после успешного изменения актива (маршруты с {asset_uid}, кроме чтения) обновить его строку
// плотного реестра, не задерживая ответ; слияние/разделение и массовые операции догонит фоновый пересчёт.
func (r *Registry) refreshHostAfter(route string, h http.Handler) http.Handler {
	if strings.HasPrefix(route, "GET ") || !strings.Contains(route, "{asset_uid}") {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(rec, req)
		uid := req.PathValue("asset_uid")
		if rec.status >= 300 || uid == "" {
			return
		}
		id, ok := access.Identity(req.Context())
		if !ok {
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if e := r.RefreshHostRegistry(ctx, id.TenantID, []string{uid}); e != nil {
				telemetry.Log(os.Stderr, "center", "host_registry_refresh_failed")
			}
		}()
	})
}
