package app

// C53.03 — функции под элементы макетов C53-mockups/6–8: счётчики меню, список компонентов, выгрузка хостов CSV,
// «Собрать по системе / компоненту» (цели SSH/WinRM/SNMP — «собрать сейчас»; агенты собирают сами по расписанию),
// «ПО и версии» и «Обращения» системы/компонента, правка компонента (роль, критичность, эталон).

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/cmdb"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

type RSMNav struct {
	Systems    int `json:"systems"`
	Components int `json:"components"`
	Hosts      int `json:"hosts"`
	Conflicts  int `json:"conflicts"`
	MyTasks    int `json:"my_tasks"` // до 999
	Tickets    int `json:"tickets_open"`
	Sites      int `json:"sites"`
}

func (r *Registry) RSMNav(ctx context.Context, id accessport.Identity) (RSMNav, error) {
	var out RSMNav
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if e = tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM cmdb.services WHERE tenant_id=$1 AND retired_at IS NULL),
(SELECT count(*) FROM cmdb.components c JOIN cmdb.environments e ON e.tenant_id=c.tenant_id AND e.environment_id=c.environment_id AND e.retired_at IS NULL
JOIN cmdb.services sv ON sv.tenant_id=e.tenant_id AND sv.service_uid=e.service_uid AND sv.retired_at IS NULL WHERE c.tenant_id=$1 AND c.retired_at IS NULL),
(SELECT count(*) FROM assets.assets WHERE tenant_id=$1 AND merged_into IS NULL AND retired_at IS NULL),
(SELECT count(*) FROM assets.reconciliation_conflicts WHERE tenant_id=$1 AND state='open'),
(SELECT count(*) FROM itsm.tickets WHERE tenant_id=$1 AND resolved_at IS NULL AND closed_at IS NULL),
(SELECT count(*) FROM scope.sites WHERE tenant_id=$1)`, id.TenantID).Scan(&out.Systems, &out.Components, &out.Hosts, &out.Conflicts, &out.Tickets, &out.Sites); e != nil {
		return out, e
	}
	mine, e := r.Owners.Worklist(ctx, tx, id.TenantID, id.UserID, "mine", "", 999)
	if e != nil {
		return out, e
	}
	out.MyTasks = len(mine)
	return out, tx.Commit(ctx)
}

type RSMComponentRow struct {
	ID          string          `json:"component_id"`
	Name        string          `json:"name"`
	Role        *string         `json:"role"`
	Critical    bool            `json:"critical"`
	SystemUID   string          `json:"service_uid"`
	System      string          `json:"system_name"`
	Environment string          `json:"environment_name"`
	EnvKind     string          `json:"environment_kind"`
	State       *cmdb.NodeState `json:"state"`
	// C53.07: эталон компонента (что должно быть на хостах) — для колонки «Эталон» реестра компонентов.
	Baseline json.RawMessage `json:"baseline"`
}

// RSMComponentCounters — полоса счётчиков раздела «Компоненты» (по всем компонентам, без учёта фильтра).
type RSMComponentCounters struct {
	Total      int `json:"total"`
	Critical   int `json:"critical"`
	Deviating  int `json:"deviating"`
	NoBaseline int `json:"no_baseline"`
	NoHosts    int `json:"no_hosts"`
}

type RSMComponentPage struct {
	Items      []RSMComponentRow    `json:"items"`
	Total      int                  `json:"total"`
	Offset     int                  `json:"offset"`
	NextOffset *int                 `json:"next_offset"`
	Counters   RSMComponentCounters `json:"counters"`
}

// RSMComponents — компоненты всех систем: сначала проблемные, поиск по имени компонента/системы.
func (r *Registry) RSMComponents(ctx context.Context, id accessport.Identity, q, filter string, offset, limit int) (RSMComponentPage, error) {
	out := RSMComponentPage{Items: []RSMComponentRow{}, Offset: offset}
	q = strings.TrimSpace(q)
	if len(q) > 128 || (filter != "" && filter != "critical" && filter != "deviating" && filter != "no_baseline" && filter != "no_hosts") {
		return out, domain.Invalid
	}
	like := "%" + strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(strings.ToLower(q)) + "%"
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	rows, e := tx.Query(ctx, `SELECT c.component_id::text,c.name,c.role,c.critical,s.service_uid::text,s.name,e.name,e.kind,ns.node_id IS NOT NULL,
COALESCE(ns.color,'grey'),COALESCE(ns.hosts,0),COALESCE(ns.green,0),COALESCE(ns.yellow,0),COALESCE(ns.red,0),COALESCE(ns.grey,0),COALESCE(ns.reasons,'[]'::jsonb),COALESCE(ns.computed_at,'epoch'::timestamptz),COALESCE(ns.fresh,0),COALESCE(ns.problems,'{}'::jsonb),c.baseline,count(*) OVER ()
FROM cmdb.components c JOIN cmdb.environments e ON e.tenant_id=c.tenant_id AND e.environment_id=c.environment_id AND e.retired_at IS NULL
JOIN cmdb.services s ON s.tenant_id=e.tenant_id AND s.service_uid=e.service_uid AND s.retired_at IS NULL
LEFT JOIN cmdb.node_states ns ON ns.tenant_id=c.tenant_id AND ns.node_kind='component' AND ns.node_id=c.component_id
WHERE c.tenant_id=$1 AND c.retired_at IS NULL AND ($2='' OR lower(c.name) LIKE $3 OR lower(s.name) LIKE $3 OR lower(COALESCE(c.role,'')) LIKE $3)
AND ($6='' OR ($6='critical' AND c.critical) OR ($6='deviating' AND COALESCE((ns.problems->>'baseline')::int,0)>0) OR ($6='no_baseline' AND c.baseline='{}'::jsonb) OR ($6='no_hosts' AND COALESCE(ns.hosts,0)=0))
ORDER BY CASE COALESCE(ns.color,'grey') WHEN 'red' THEN 0 WHEN 'yellow' THEN 1 WHEN 'grey' THEN 2 ELSE 3 END,lower(s.name),lower(c.name) OFFSET $4 LIMIT $5`, id.TenantID, q, like, offset, limit+1, filter)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		var x RSMComponentRow
		var has bool
		var st cmdb.NodeState
		if e = rows.Scan(&x.ID, &x.Name, &x.Role, &x.Critical, &x.SystemUID, &x.System, &x.Environment, &x.EnvKind, &has, &st.Color, &st.Hosts, &st.Green, &st.Yellow, &st.Red, &st.Grey, &st.Reasons, &st.ComputedAt, &st.Fresh, &st.Problems, &x.Baseline, &out.Total); e != nil {
			return out, e
		}
		if has {
			st.Kind, st.ID = "component", x.ID
			x.State = &st
		}
		out.Items = append(out.Items, x)
	}
	if e = rows.Err(); e != nil {
		return out, e
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		next := offset + limit
		out.NextOffset = &next
	}
	c := &out.Counters
	if e = tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE c.critical),count(*) FILTER (WHERE COALESCE((ns.problems->>'baseline')::int,0)>0),count(*) FILTER (WHERE c.baseline='{}'::jsonb),count(*) FILTER (WHERE COALESCE(ns.hosts,0)=0)
FROM cmdb.components c JOIN cmdb.environments e ON e.tenant_id=c.tenant_id AND e.environment_id=c.environment_id AND e.retired_at IS NULL
JOIN cmdb.services s ON s.tenant_id=e.tenant_id AND s.service_uid=e.service_uid AND s.retired_at IS NULL
LEFT JOIN cmdb.node_states ns ON ns.tenant_id=c.tenant_id AND ns.node_kind='component' AND ns.node_id=c.component_id
WHERE c.tenant_id=$1 AND c.retired_at IS NULL`, id.TenantID).Scan(&c.Total, &c.Critical, &c.Deviating, &c.NoBaseline, &c.NoHosts); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

// rsmScopeHosts — хосты системы (все компоненты) или компонента.
func rsmScopeHosts(ctx context.Context, tx pgx.Tx, tenant, kind, id string) ([]string, error) {
	if kind == "asset" {
		return []string{id}, nil
	}
	var q string
	if kind == "system" {
		q = `SELECT DISTINCT b.asset_uid::text FROM cmdb.bindings b JOIN cmdb.components c ON c.tenant_id=b.tenant_id AND c.component_id=b.component_id
JOIN cmdb.environments e ON e.tenant_id=c.tenant_id AND e.environment_id=c.environment_id WHERE b.tenant_id=$1 AND e.service_uid=$2 AND b.valid_to IS NULL AND b.status='active'`
	} else {
		q = `SELECT DISTINCT asset_uid::text FROM cmdb.bindings WHERE tenant_id=$1 AND component_id=$2 AND valid_to IS NULL AND status='active'`
	}
	rows, e := tx.Query(ctx, q, tenant, id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var u string
		if e = rows.Scan(&u); e != nil {
			return nil, e
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func rsmScopeExists(ctx context.Context, tx pgx.Tx, tenant, kind, id string) error {
	if !identifier.Valid(id) {
		return domain.NotFound
	}
	q := "SELECT EXISTS(SELECT 1 FROM cmdb.services WHERE tenant_id=$1 AND service_uid=$2 AND retired_at IS NULL)"
	if kind == "component" {
		q = "SELECT EXISTS(SELECT 1 FROM cmdb.components WHERE tenant_id=$1 AND component_id=$2 AND retired_at IS NULL)"
	}
	if kind == "asset" {
		q = "SELECT EXISTS(SELECT 1 FROM assets.assets WHERE tenant_id=$1 AND asset_uid=$2 AND merged_into IS NULL)"
	}
	var ok bool
	if e := tx.QueryRow(ctx, q, tenant, id).Scan(&ok); e != nil {
		return e
	}
	if !ok {
		return domain.NotFound
	}
	return nil
}

// RSMHostsCSV — выгрузка хостов системы/компонента (UTF-8 с BOM, «;»): имя, UID, IP, площадка, компонент, среда,
// цвет, причины, последняя инвентаризация.
func (r *Registry) RSMHostsCSV(ctx context.Context, id accessport.Identity, kind, scope string) ([]byte, error) {
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	if e = rsmScopeExists(ctx, tx, id.TenantID, kind, scope); e != nil {
		return nil, e
	}
	cond := "e.service_uid=$2"
	if kind == "component" {
		cond = "c.component_id=$2"
	}
	rows, e := tx.Query(ctx, `SELECT b.asset_uid::text,COALESCE(st.name,''),c.name,e.name,COALESCE(h.color,'grey'),COALESCE(h.reasons::text,'[]'),h.last_inventory_at
FROM cmdb.bindings b JOIN cmdb.components c ON c.tenant_id=b.tenant_id AND c.component_id=b.component_id JOIN cmdb.environments e ON e.tenant_id=c.tenant_id AND e.environment_id=c.environment_id
JOIN assets.assets a ON a.tenant_id=b.tenant_id AND a.asset_uid=b.asset_uid LEFT JOIN scope.sites st ON st.tenant_id=a.tenant_id AND st.site_id=a.site_id
LEFT JOIN cmdb.host_states h ON h.tenant_id=b.tenant_id AND h.asset_uid=b.asset_uid
WHERE b.tenant_id=$1 AND `+cond+` AND b.valid_to IS NULL AND b.status='active' ORDER BY e.name,c.name,b.asset_uid LIMIT 200000`, id.TenantID, scope)
	if e != nil {
		return nil, e
	}
	type row struct{ uid, site, comp, env, color, reasons, last string }
	list := []row{}
	uids := []string{}
	for rows.Next() {
		var x row
		var last *time.Time
		if e = rows.Scan(&x.uid, &x.site, &x.comp, &x.env, &x.color, &x.reasons, &last); e != nil {
			rows.Close()
			return nil, e
		}
		if last != nil {
			x.last = last.UTC().Format(time.RFC3339)
		}
		list = append(list, x)
		uids = append(uids, x.uid)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return nil, e
	}
	names, e := rsmNames(ctx, tx, id.TenantID, uids)
	if e != nil {
		return nil, e
	}
	ips, e := rsmIPs(ctx, tx, id.TenantID, uids)
	if e != nil {
		return nil, e
	}
	var buf bytes.Buffer
	buf.WriteString("\uFEFF")
	w := csv.NewWriter(&buf)
	w.Comma, w.UseCRLF = ';', true
	_ = w.Write([]string{"host", "asset_uid", "ip", "site", "component", "environment", "state", "reasons", "last_inventory_at"})
	for _, x := range list {
		_ = w.Write([]string{csvCell(names[x.uid]), x.uid, ips[x.uid], csvCell(x.site), csvCell(x.comp), csvCell(x.env), x.color, csvCell(x.reasons), x.last})
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

type RSMCollectResult struct {
	Hosts     int `json:"hosts"`
	Requested int `json:"requested"` // целей сбора, которым отправлено «собрать сейчас»
	Recent    int `json:"recent"`    // цели, уже запрошенные за последние 2 минуты
	Agents    int `json:"agents"`    // хосты с агентом (соберут по своему расписанию)
	NoTarget  int `json:"no_target"` // хосты без цели и без агента (portable, импорт)
}

// RSMCollect — «Собрать по системе / компоненту»: всем активным целям сбора хостов — «собрать сейчас».
func (r *Registry) RSMCollect(ctx context.Context, id accessport.Identity, kind, scope string) (RSMCollectResult, error) {
	var out RSMCollectResult
	tx, e := r.assetOperationTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if e = rsmScopeExists(ctx, tx, id.TenantID, kind, scope); e != nil {
		return out, e
	}
	hosts, e := rsmScopeHosts(ctx, tx, id.TenantID, kind, scope)
	if e != nil {
		return out, e
	}
	out.Hosts = len(hosts)
	if len(hosts) == 0 {
		return out, tx.Commit(ctx)
	}
	if e = tx.QueryRow(ctx, `WITH t AS (SELECT DISTINCT t.target_id,t.collect_requested_at FROM sources.remote_targets t JOIN assets.source_records r ON r.tenant_id=t.tenant_id AND r.source_id=t.agent_source_id
WHERE t.tenant_id=$1 AND r.asset_uid=ANY($2::uuid[]) AND t.state<>'disabled'),
upd AS (UPDATE sources.remote_targets x SET collect_requested_at=now() FROM t WHERE x.tenant_id=$1 AND x.target_id=t.target_id AND (t.collect_requested_at IS NULL OR t.collect_requested_at<now()-interval '2 minutes') RETURNING 1)
SELECT (SELECT count(*) FROM upd),(SELECT count(*) FROM t)`, id.TenantID, hosts).Scan(&out.Requested, &out.Recent); e != nil {
		return out, e
	}
	out.Recent -= out.Requested
	if e = tx.QueryRow(ctx, `SELECT count(DISTINCT r.asset_uid) FILTER (WHERE s.source_kind='agent' AND NOT EXISTS(SELECT 1 FROM sources.remote_targets t WHERE t.tenant_id=s.tenant_id AND t.agent_source_id=s.source_id)),
$3::int-count(DISTINCT r.asset_uid) FILTER (WHERE s.source_kind='agent')
FROM assets.source_records r JOIN sources.sources s ON s.tenant_id=r.tenant_id AND s.source_id=r.source_id WHERE r.tenant_id=$1 AND r.asset_uid=ANY($2::uuid[])`, id.TenantID, hosts, len(hosts)).Scan(&out.Agents, &out.NoTarget); e != nil {
		return out, e
	}
	if out.NoTarget < 0 {
		out.NoTarget = 0
	}
	if e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "cmdb.rsm_collect_requested", kind, scope); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

type RSMSoftwareVersion struct {
	Version string `json:"version"`
	Hosts   int    `json:"hosts"`
}

type RSMSoftwareProduct struct {
	Name     string               `json:"name"`
	Hosts    int                  `json:"hosts"`
	Versions []RSMSoftwareVersion `json:"versions"`
}

type RSMSoftwarePage struct {
	Hosts     int                  `json:"hosts"`
	Products  []RSMSoftwareProduct `json:"products"`
	Truncated bool                 `json:"truncated"`
}

// RSMSoftware — «ПО и версии»: установленное ПО по хостам системы/компонента, версии с числом хостов; расхождение
// версий видно сразу (у продукта больше одной версии). q — подстрока названия.
func (r *Registry) RSMSoftware(ctx context.Context, id accessport.Identity, kind, scope, q string) (RSMSoftwarePage, error) {
	out := RSMSoftwarePage{Products: []RSMSoftwareProduct{}}
	q = strings.ToLower(strings.TrimSpace(q))
	if len(q) > 128 {
		return out, domain.Invalid
	}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if e = rsmScopeExists(ctx, tx, id.TenantID, kind, scope); e != nil {
		return out, e
	}
	hosts, e := rsmScopeHosts(ctx, tx, id.TenantID, kind, scope)
	if e != nil {
		return out, e
	}
	out.Hosts = len(hosts)
	like := "%" + strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(q) + "%"
	rows, e := tx.Query(ctx, `SELECT n.value #>> '{}',COALESCE(v.value #>> '{}',''),count(DISTINCT n.asset_uid) FROM inventory.record_facts12 n
LEFT JOIN inventory.record_facts12 v ON v.tenant_id=n.tenant_id AND v.asset_uid=n.asset_uid AND v.section_name='software' AND v.record_key=n.record_key AND v.field_name='version'
WHERE n.tenant_id=$1 AND n.asset_uid=ANY($2::uuid[]) AND n.section_name='software' AND n.field_name='name' AND jsonb_typeof(n.value)='string' AND ($3='' OR lower(n.value #>> '{}') LIKE $4)
GROUP BY 1,2 ORDER BY lower(n.value #>> '{}'),2 LIMIT 5001`, id.TenantID, hosts, q, like)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	by := map[string]*RSMSoftwareProduct{}
	order := []string{}
	n := 0
	for rows.Next() {
		var name, version string
		var hostsN int
		if e = rows.Scan(&name, &version, &hostsN); e != nil {
			return out, e
		}
		if n++; n > 5000 {
			out.Truncated = true
			break
		}
		p := by[name]
		if p == nil {
			p = &RSMSoftwareProduct{Name: name, Versions: []RSMSoftwareVersion{}}
			by[name], order = p, append(order, name)
		}
		p.Versions = append(p.Versions, RSMSoftwareVersion{Version: version, Hosts: hostsN})
		p.Hosts += hostsN
	}
	if e = rows.Err(); e != nil {
		return out, e
	}
	for _, k := range order {
		p := by[k]
		sort.Slice(p.Versions, func(i, j int) bool { return p.Versions[i].Hosts > p.Versions[j].Hosts })
		out.Products = append(out.Products, *p)
	}
	return out, tx.Commit(ctx)
}

type RSMTicket struct {
	ID       string    `json:"ticket_id"`
	Number   string    `json:"number"`
	Kind     string    `json:"kind"`
	Title    string    `json:"title"`
	State    string    `json:"state"`
	Priority int       `json:"priority"`
	Created  time.Time `json:"created_at"`
	Open     bool      `json:"open"`
}

type RSMTicketList struct {
	Items []RSMTicket `json:"items"`
	Open  int         `json:"open"`
}

// RSMTickets — обращения, связанные с системой (сервис C26) или с её/компонента хостами; открытые сверху.
func (r *Registry) RSMTickets(ctx context.Context, id accessport.Identity, kind, scope string) (RSMTicketList, error) {
	out := RSMTicketList{Items: []RSMTicket{}}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if e = rsmScopeExists(ctx, tx, id.TenantID, kind, scope); e != nil {
		return out, e
	}
	hosts, e := rsmScopeHosts(ctx, tx, id.TenantID, kind, scope)
	if e != nil {
		return out, e
	}
	service := ""
	if kind == "system" {
		service = scope
	}
	rows, e := tx.Query(ctx, `SELECT DISTINCT t.ticket_id::text,t.number,t.kind,t.title,t.state,t.priority,t.created_at,(t.resolved_at IS NULL AND t.closed_at IS NULL)
FROM itsm.tickets t JOIN itsm.ticket_links l ON l.tenant_id=t.tenant_id AND l.ticket_id=t.ticket_id
WHERE t.tenant_id=$1 AND ((l.target_kind='service' AND l.target_id::text=$2) OR (l.target_kind='asset' AND l.target_id=ANY($3::uuid[])))
ORDER BY 8 DESC,7 DESC LIMIT 200`, id.TenantID, service, hosts)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		var x RSMTicket
		if e = rows.Scan(&x.ID, &x.Number, &x.Kind, &x.Title, &x.State, &x.Priority, &x.Created, &x.Open); e != nil {
			return out, e
		}
		x.Created = x.Created.UTC()
		if x.Open {
			out.Open++
		}
		out.Items = append(out.Items, x)
	}
	return out, rows.Err()
}

// rsmMoreHandlers — маршруты этого файла (подключаются в rsmHandlers).
func (r *Registry) rsmMoreHandlers(h map[string]rsmRoute) {
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
	h["GET /api/v1/rsm/nav"] = read(func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		out, e := r.RSMNav(ctx, id)
		reply(w, req, out, e)
	})
	h["GET /api/v1/rsm/components"] = read(func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity) {
		q, ok := queryOnly(w, req, "q", "filter", "offset", "limit")
		if !ok {
			return
		}
		offset, limit, ok := offsetLimit(w, q)
		if !ok {
			return
		}
		out, e := r.RSMComponents(ctx, id, q.Get("q"), q.Get("filter"), offset, limit)
		reply(w, req, out, e)
	})
	for _, kind := range []string{"system", "component"} {
		kind := kind
		base, param := "/api/v1/rsm/systems/{service_uid}", "service_uid"
		if kind == "component" {
			base, param = "/api/v1/rsm/components/{component_id}", "component_id"
		}
		h["GET "+base+"/hosts.csv"] = read(func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity) {
			if _, ok := queryOnly(w, req); !ok {
				return
			}
			raw, e := r.RSMHostsCSV(ctx, id, kind, req.PathValue(param))
			if e != nil {
				cmdbError(w, req, e)
				return
			}
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			w.Header().Set("Content-Disposition", `attachment; filename="takt-`+kind+`-hosts.csv"`)
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			_, _ = w.Write(raw)
		})
		h["GET "+base+"/software"] = read(func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity) {
			q, ok := queryOnly(w, req, "q")
			if !ok {
				return
			}
			out, e := r.RSMSoftware(ctx, id, kind, req.PathValue(param), q.Get("q"))
			reply(w, req, out, e)
		})
		h["GET "+base+"/tickets"] = read(func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity) {
			if _, ok := queryOnly(w, req); !ok {
				return
			}
			out, e := r.RSMTickets(ctx, id, kind, req.PathValue(param))
			reply(w, req, out, e)
		})
		h["POST "+base+"/collect"] = rsmRoute{"assets:write", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var body struct{}
			if !readOperationBody(w, req, &body) {
				return
			}
			ctx, cancel, id := cmdbContext(req)
			defer cancel()
			out, e := r.RSMCollect(ctx, id, kind, req.PathValue(param))
			reply(w, req, out, e)
		})}
	}
	h["GET /api/v1/rsm/components/{component_id}/changes"] = read(func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		out, e := r.RSMComponentChanges(ctx, id, req.PathValue("component_id"))
		reply(w, req, out, e)
	})
	type compPatch struct {
		Revision string `json:"revision"`
		cmdb.ComponentFields
	}
	h["PATCH /api/v1/rsm/components/{component_id}"] = rsmRoute{"assets:write", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body compPatch
		if !readOperationBody(w, req, &body) {
			return
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		var out cmdb.Component
		uid := req.PathValue("component_id")
		e := r.rsmWrite(ctx, id, "component_updated", "component", func(tx pgx.Tx) (string, error) {
			var e error
			out, e = r.CMDB.UpdateComponent(ctx, tx, id.TenantID, uid, body.Revision, id.UserID, body.ComponentFields)
			return uid, e
		})
		reply(w, req, out, e)
	})}
}

type RSMChangeList struct {
	Changes []RSMChange `json:"changes"`
	Total   int         `json:"total"`
}

// RSMComponentChanges — изменения компонента за 7 дней: сам компонент, его привязки и правила, история его хостов.
func (r *Registry) RSMComponentChanges(ctx context.Context, id accessport.Identity, component string) (RSMChangeList, error) {
	out := RSMChangeList{Changes: []RSMChange{}}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if e = rsmScopeExists(ctx, tx, id.TenantID, "component", component); e != nil {
		return out, e
	}
	if out.Changes, out.Total, e = r.rsmChanges(ctx, tx, id.TenantID, component, nil, []string{component}, 7); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}
