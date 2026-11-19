package app

import (
	"context"
	"encoding/csv"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/cmdb"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// C53.04 — плотный реестр хостов: страница (фильтры, сортировка, 100/250/500), счётчики, дерево группировки,
// выгрузка CSV по фильтру, массовые «назначить ответственного» и «собрать сейчас» (по выбору или по фильтру).

type HostRegistryPage struct {
	Items    []cmdb.HostRegistryRow `json:"items"`
	Total    int                    `json:"total"`
	Offset   int                    `json:"offset"`
	Limit    int                    `json:"limit"`
	Counters cmdb.HostCounters      `json:"counters"`
}

type HostTree struct {
	By    string              `json:"by"`
	Nodes []cmdb.HostTreeNode `json:"nodes"`
}

// HostBulkRequest — выбор хостов: явный список (до 1000) или фильтр реестра (берутся первые 1000 по имени).
type HostBulkRequest struct {
	AssetUIDs []string          `json:"asset_uids,omitempty"`
	Filter    map[string]string `json:"filter,omitempty"`
	Role      string            `json:"role,omitempty"`
	Subject   string            `json:"subject_id,omitempty"`
}

type HostBulkResult struct {
	Hosts     int `json:"hosts"`
	Applied   int `json:"applied"`
	Unchanged int `json:"unchanged"`
	Requested int `json:"requested"`
	Agents    int `json:"agents"`
	NoTarget  int `json:"no_target"`
}

const hostBulkMax = 1000

var hostFilterKeys = []string{"q", "site", "segment", "class", "os_family", "os", "owner", "team", "system", "component", "freshness"}

func hostFilterOf(get func(string) string) cmdb.HostFilter {
	return cmdb.HostFilter{Query: strings.TrimSpace(get("q")), Site: get("site"), Segment: get("segment"), Class: get("class"), OSFamily: get("os_family"), OS: get("os"),
		Owner: get("owner"), Team: get("team"), System: get("system"), Component: get("component"), Freshness: get("freshness")}
}

func (r *Registry) HostRegistry(ctx context.Context, id accessport.Identity, f cmdb.HostFilter) (HostRegistryPage, error) {
	out := HostRegistryPage{Items: []cmdb.HostRegistryRow{}, Offset: f.Offset, Limit: f.Limit}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if out.Items, out.Total, e = r.CMDB.HostRegistryPage(ctx, tx, id.TenantID, f); e != nil {
		return out, e
	}
	if out.Limit != 250 && out.Limit != 500 {
		out.Limit = 100
	}
	if out.Counters, e = r.CMDB.HostRegistryCounters(ctx, tx, id.TenantID); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

func (r *Registry) HostRegistryTree(ctx context.Context, id accessport.Identity, by string) (HostTree, error) {
	out := HostTree{By: by}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if out.Nodes, e = r.CMDB.HostRegistryTree(ctx, tx, id.TenantID, by); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

// hostBulkUIDs — хосты массовой операции: явный список (проверенные UUID) или фильтр реестра.
func (r *Registry) hostBulkUIDs(ctx context.Context, id accessport.Identity, req HostBulkRequest) ([]string, error) {
	if len(req.AssetUIDs) > 0 {
		if len(req.AssetUIDs) > hostBulkMax || req.Filter != nil {
			return nil, domain.Invalid
		}
		seen := map[string]bool{}
		out := []string{}
		for _, u := range req.AssetUIDs {
			if !identifier.Valid(u) {
				return nil, domain.Invalid
			}
			if !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}
		return out, nil
	}
	if req.Filter == nil {
		return nil, domain.Invalid
	}
	for k := range req.Filter {
		known := false
		for _, x := range hostFilterKeys {
			known = known || x == k
		}
		if !known {
			return nil, domain.Invalid
		}
	}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	uids, e := r.CMDB.HostRegistryUIDs(ctx, tx, id.TenantID, hostFilterOf(func(k string) string { return req.Filter[k] }), hostBulkMax)
	if e != nil {
		return nil, e
	}
	return uids, tx.Commit(ctx)
}

// HostBulkAssign — назначить роль выбранным хостам по их текущим версиям (пачками по 200, как массовое назначение).
func (r *Registry) HostBulkAssign(ctx context.Context, id accessport.Identity, req HostBulkRequest) (HostBulkResult, error) {
	out := HostBulkResult{}
	uids, e := r.hostBulkUIDs(ctx, id, req)
	if e != nil {
		return out, e
	}
	out.Hosts = len(uids)
	for i := 0; i < len(uids); i += 200 {
		batch := uids[i:min(i+200, len(uids))]
		tx, e := r.readTx(ctx, id)
		if e != nil {
			return out, e
		}
		_, versions, e := r.Assets.GetMany(ctx, tx, id.TenantID, batch)
		tx.Rollback(ctx)
		if e != nil {
			return out, e
		}
		items := []BulkItem{}
		for _, u := range batch {
			if v, ok := versions[u]; ok {
				items = append(items, BulkItem{Asset: u, ExpectedVersion: v})
			}
		}
		if len(items) == 0 {
			continue
		}
		res, e := r.BulkAssign(ctx, id, BulkAssignRequest{Role: req.Role, Subject: req.Subject, Items: items})
		if e != nil {
			return out, e
		}
		out.Applied += res.Applied
		out.Unchanged += res.Unchanged
		_ = r.RefreshHostRegistry(ctx, id.TenantID, batch)
	}
	return out, nil
}

// HostBulkCollect — запросить внеочередной сбор у целей выбранных хостов.
func (r *Registry) HostBulkCollect(ctx context.Context, id accessport.Identity, req HostBulkRequest) (HostBulkResult, error) {
	out := HostBulkResult{}
	uids, e := r.hostBulkUIDs(ctx, id, req)
	if e != nil {
		return out, e
	}
	out.Hosts = len(uids)
	for _, u := range uids {
		res, e := r.RSMCollect(ctx, id, "asset", u)
		if e != nil {
			return out, e
		}
		out.Requested += res.Requested + res.Recent
		out.Agents += res.Agents
		out.NoTarget += res.NoTarget
	}
	return out, nil
}

// HostRegistryCSV — выгрузка по фильтру (до 100 тыс. строк) с BOM и «;» для Excel.
func (r *Registry) HostRegistryCSV(ctx context.Context, id accessport.Identity, f cmdb.HostFilter, w http.ResponseWriter) error {
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", `attachment; filename="hosts.csv"`)
	_, _ = w.Write([]byte("\ufeff"))
	c := csv.NewWriter(w)
	c.Comma = ';'
	_ = c.Write([]string{"Имя", "IP", "ОС", "Тип", "Площадка", "Сегмент", "Свежесть", "Разделы", "Источники", "Ответственный", "Команда", "Система", "Компонент", "Последний сбор", "asset_uid"})
	f.Limit = 500
	for f.Offset = 0; f.Offset < 100000; f.Offset += 500 {
		rows, _, e := r.CMDB.HostRegistryPage(ctx, tx, id.TenantID, f)
		if e != nil {
			return e
		}
		for _, x := range rows {
			last := ""
			if x.LastInventory != nil {
				last = x.LastInventory.UTC().Format(time.RFC3339)
			}
			_ = c.Write([]string{x.Name, x.IP, x.OS, x.Class, x.SiteName, x.Segment, x.Freshness, strconv.Itoa(x.SectionsOK) + "/" + strconv.Itoa(x.SectionsTotal), strings.Join(x.Sources, ","), x.Accountable, x.Team, x.System, x.Component, last, x.AssetUID})
		}
		if len(rows) < 500 {
			break
		}
	}
	c.Flush()
	return tx.Commit(ctx)
}

func (r *Registry) hostRegistryHandlers(h map[string]rsmRoute) {
	read := func(fn func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity)) rsmRoute {
		return rsmRoute{"assets:read", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx, cancel, id := cmdbContext(req)
			defer cancel()
			fn(w, req, ctx, id)
		})}
	}
	reply := func(w http.ResponseWriter, req *http.Request, out any, e error) {
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, out)
	}
	filter := func(w http.ResponseWriter, req *http.Request, extra ...string) (cmdb.HostFilter, url.Values, bool) {
		q, ok := queryOnly(w, req, append(append([]string{}, hostFilterKeys...), extra...)...)
		if !ok {
			return cmdb.HostFilter{}, nil, false
		}
		return hostFilterOf(q.Get), q, true
	}
	h["GET /api/v1/hosts"] = read(func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity) {
		f, q, ok := filter(w, req, "sort", "dir", "offset", "limit")
		if !ok {
			return
		}
		var e error
		if v := q.Get("offset"); v != "" {
			if f.Offset, e = strconv.Atoi(v); e != nil {
				cmdbError(w, req, domain.Invalid)
				return
			}
		}
		if v := q.Get("limit"); v != "" {
			if f.Limit, e = strconv.Atoi(v); e != nil || (f.Limit != 100 && f.Limit != 250 && f.Limit != 500) {
				cmdbError(w, req, domain.Invalid)
				return
			}
		}
		f.Sort, f.Desc = q.Get("sort"), q.Get("dir") == "desc"
		if d := q.Get("dir"); d != "" && d != "asc" && d != "desc" {
			cmdbError(w, req, domain.Invalid)
			return
		}
		out, e := r.HostRegistry(ctx, id, f)
		reply(w, req, out, e)
	})
	h["GET /api/v1/hosts/tree"] = read(func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity) {
		q, ok := queryOnly(w, req, "by")
		if !ok {
			return
		}
		out, e := r.HostRegistryTree(ctx, id, q.Get("by"))
		reply(w, req, out, e)
	})
	h["GET /api/v1/hosts.csv"] = read(func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity) {
		f, q, ok := filter(w, req, "sort", "dir")
		if !ok {
			return
		}
		f.Sort, f.Desc = q.Get("sort"), q.Get("dir") == "desc"
		if e := r.HostRegistryCSV(ctx, id, f, w); e != nil {
			cmdbError(w, req, e)
		}
	})
	write := func(permission string, fn func(ctx context.Context, id accessport.Identity, body HostBulkRequest) (HostBulkResult, error)) rsmRoute {
		return rsmRoute{permission, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var body HostBulkRequest
			if !readOperationBody(w, req, &body) {
				return
			}
			ctx, cancel, id := cmdbContext(req)
			defer cancel()
			out, e := fn(ctx, id, body)
			reply(w, req, out, e)
		})}
	}
	h["GET /api/v1/rsm/health/sites"] = read(func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		out, e := r.RSMSiteHealth(ctx, id)
		reply(w, req, out, e)
	})
	h["POST /api/v1/hosts/assign"] = write("assets:write", r.HostBulkAssign)
	h["POST /api/v1/hosts/collect"] = write("assets:write", r.HostBulkCollect)
}

// RSMSiteHealth — разрез «Здоровья» по площадкам (C53.06): цвета хостов площадки и системы, чьи хосты на ней.
type RSMSiteSystem struct {
	UID         string `json:"service_uid"`
	Name        string `json:"name"`
	Criticality string `json:"criticality"`
	Hosts       int    `json:"hosts"`
	Green       int    `json:"green"`
	Yellow      int    `json:"yellow"`
	Red         int    `json:"red"`
	Grey        int    `json:"grey"`
}

type RSMSiteHealth struct {
	SiteID  string          `json:"site_id"`
	Name    string          `json:"name"`
	Hosts   int             `json:"hosts"`
	Green   int             `json:"green"`
	Yellow  int             `json:"yellow"`
	Red     int             `json:"red"`
	Grey    int             `json:"grey"`
	Systems []RSMSiteSystem `json:"systems"`
}

type RSMSiteHealthList struct {
	Items []RSMSiteHealth `json:"items"`
}

func (r *Registry) RSMSiteHealth(ctx context.Context, id accessport.Identity) (RSMSiteHealthList, error) {
	out := RSMSiteHealthList{Items: []RSMSiteHealth{}}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	rows, e := tx.Query(ctx, `SELECT st.site_id::text,st.name,count(*),count(*) FILTER (WHERE COALESCE(hs.color,'grey')='green'),count(*) FILTER (WHERE hs.color='yellow'),count(*) FILTER (WHERE hs.color='red'),count(*) FILTER (WHERE COALESCE(hs.color,'grey')='grey')
FROM assets.assets a JOIN scope.sites st ON st.tenant_id=a.tenant_id AND st.site_id=a.site_id LEFT JOIN cmdb.host_states hs ON hs.tenant_id=a.tenant_id AND hs.asset_uid=a.asset_uid
WHERE a.tenant_id=$1 AND a.merged_into IS NULL AND a.retired_at IS NULL GROUP BY 1,2 ORDER BY count(*) FILTER (WHERE hs.color='red') DESC,2`, id.TenantID)
	if e != nil {
		return out, e
	}
	index := map[string]int{}
	for rows.Next() {
		var s RSMSiteHealth
		if e = rows.Scan(&s.SiteID, &s.Name, &s.Hosts, &s.Green, &s.Yellow, &s.Red, &s.Grey); e != nil {
			rows.Close()
			return out, e
		}
		s.Systems = []RSMSiteSystem{}
		index[s.SiteID] = len(out.Items)
		out.Items = append(out.Items, s)
	}
	rows.Close()
	rows, e = tx.Query(ctx, `SELECT a.site_id::text,s.service_uid::text,s.name,s.criticality,count(DISTINCT a.asset_uid),count(DISTINCT a.asset_uid) FILTER (WHERE COALESCE(hs.color,'grey')='green'),
count(DISTINCT a.asset_uid) FILTER (WHERE hs.color='yellow'),count(DISTINCT a.asset_uid) FILTER (WHERE hs.color='red'),count(DISTINCT a.asset_uid) FILTER (WHERE COALESCE(hs.color,'grey')='grey')
FROM cmdb.bindings b JOIN cmdb.components c ON c.tenant_id=b.tenant_id AND c.component_id=b.component_id AND c.retired_at IS NULL
JOIN cmdb.environments e ON e.tenant_id=c.tenant_id AND e.environment_id=c.environment_id AND e.retired_at IS NULL
JOIN cmdb.services s ON s.tenant_id=e.tenant_id AND s.service_uid=e.service_uid AND s.retired_at IS NULL
JOIN assets.assets a ON a.tenant_id=b.tenant_id AND a.asset_uid=b.asset_uid AND a.merged_into IS NULL AND a.retired_at IS NULL
LEFT JOIN cmdb.host_states hs ON hs.tenant_id=a.tenant_id AND hs.asset_uid=a.asset_uid
WHERE b.tenant_id=$1 AND b.valid_to IS NULL AND b.status='active' GROUP BY 1,2,3,4 ORDER BY 8 DESC,7 DESC,3`, id.TenantID)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		var site string
		var x RSMSiteSystem
		if e = rows.Scan(&site, &x.UID, &x.Name, &x.Criticality, &x.Hosts, &x.Green, &x.Yellow, &x.Red, &x.Grey); e != nil {
			return out, e
		}
		if i, ok := index[site]; ok {
			out.Items[i].Systems = append(out.Items[i].Systems, x)
		}
	}
	if e = rows.Err(); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}
