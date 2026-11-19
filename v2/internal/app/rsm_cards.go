package app

// C53.03 — данные карточек по макетам C53-mockups/7 (система) и 8 (компонент): матрица «компонент × среда»,
// «требует внимания» (проблемные хосты, сгруппированные по причине), зависимости с цветом и критичностью, изменения
// за 7 дней (история cmdb и активов системы), ответственные; для компонента — площадки, сети, сводка эталона и
// строки хостов с IP, площадкой и значениями из эталона. Только чтение; всё из уже собранных данных.

import (
	"context"
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/cmdb"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

type RSMMatrixCell struct {
	ComponentID string `json:"component_id"`
	Hosts       int    `json:"hosts"`
}

type RSMMatrixRow struct {
	Name     string                   `json:"name"`
	Critical bool                     `json:"critical"`
	Color    string                   `json:"color"`
	Cells    map[string]RSMMatrixCell `json:"cells"` // вид среды → компонент
	Problems map[string]int           `json:"problems"`
}

type RSMAttention struct {
	Color       string        `json:"color"`
	Code        string        `json:"code"`
	Detail      string        `json:"detail"`
	Component   string        `json:"component_name"`
	ComponentID string        `json:"component_id"`
	Environment string        `json:"environment_name"`
	Hosts       []RSMAssetRef `json:"hosts"`
	Total       int           `json:"total"`
}

type RSMDependency struct {
	UID         string         `json:"service_uid"`
	Name        string         `json:"name"`
	Criticality string         `json:"criticality"`
	Color       string         `json:"color"`
	Problems    map[string]int `json:"problems"`
}

type RSMChange struct {
	At        time.Time       `json:"occurred_at"`
	Source    string          `json:"source"` // cmdb | asset
	Object    string          `json:"object_type"`
	Action    string          `json:"action"`
	Detail    json.RawMessage `json:"detail"`
	AssetUID  *string         `json:"asset_uid"`
	AssetName string          `json:"asset_name"`
}

type RSMSystemCard struct {
	System        cmdb.System     `json:"system"`
	State         *cmdb.NodeState `json:"state"`
	DirectionName *string         `json:"direction_name"`
	ITSubjectName *string         `json:"it_subject_name"`
	Sites         int             `json:"sites"`
	EnvKinds      []string        `json:"env_kinds"`
	Matrix        []RSMMatrixRow  `json:"matrix"`
	Attention     []RSMAttention  `json:"attention"`
	DependsOn     []RSMDependency `json:"depends_on"`
	Dependents    []RSMDependency `json:"dependents"`
	Changes       []RSMChange     `json:"changes"`
	ChangesTotal  int             `json:"changes_total"`
}

var envOrder = map[string]int{"prod": 0, "dr": 1, "stage": 2, "test": 3, "dev": 4, "other": 5}

func (r *Registry) RSMSystemCard(ctx context.Context, id accessport.Identity, uid string) (RSMSystemCard, error) {
	out := RSMSystemCard{EnvKinds: []string{}, Matrix: []RSMMatrixRow{}, Attention: []RSMAttention{}, DependsOn: []RSMDependency{}, Dependents: []RSMDependency{}, Changes: []RSMChange{}}
	if !identifier.Valid(uid) {
		return out, domain.NotFound
	}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if out.System, e = r.CMDB.System(ctx, tx, id.TenantID, uid); e != nil {
		return out, e
	}
	if out.System.DirectionUID != nil {
		var n string
		if tx.QueryRow(ctx, "SELECT name FROM cmdb.directions WHERE tenant_id=$1 AND direction_uid=$2", id.TenantID, *out.System.DirectionUID).Scan(&n) == nil {
			out.DirectionName = &n
		}
	}
	if out.System.ITSubjectID != nil {
		var n string
		if tx.QueryRow(ctx, "SELECT name FROM responsibility.subjects WHERE tenant_id=$1 AND subject_id=$2", id.TenantID, *out.System.ITSubjectID).Scan(&n) == nil {
			out.ITSubjectName = &n
		}
	}
	envs, comps, e := r.CMDB.SystemEnvironments(ctx, tx, id.TenantID, uid)
	if e != nil {
		return out, e
	}
	compIDs, envIDs := []string{}, []string{}
	envByID := map[string]cmdb.Environment{}
	kinds := map[string]bool{}
	for _, x := range envs {
		envIDs = append(envIDs, x.ID)
		envByID[x.ID] = x
		kinds[x.Kind] = true
		for _, c := range comps[x.ID] {
			compIDs = append(compIDs, c.ID)
		}
	}
	for k := range kinds {
		out.EnvKinds = append(out.EnvKinds, k)
	}
	sort.Slice(out.EnvKinds, func(i, j int) bool { return envOrder[out.EnvKinds[i]] < envOrder[out.EnvKinds[j]] })
	states, e := r.CMDB.NodeStates(ctx, tx, id.TenantID, "system", []string{uid})
	if e != nil {
		return out, e
	}
	out.State = nodePtr(states, uid)
	compStates, e := r.CMDB.NodeStates(ctx, tx, id.TenantID, "component", compIDs)
	if e != nil {
		return out, e
	}
	// матрица: компоненты с одинаковым именем в разных средах — одна строка
	rows := map[string]*RSMMatrixRow{}
	order := []string{}
	for _, x := range envs {
		for _, c := range comps[x.ID] {
			key := strings.ToLower(c.Name)
			row := rows[key]
			if row == nil {
				row = &RSMMatrixRow{Name: c.Name, Color: "grey", Cells: map[string]RSMMatrixCell{}, Problems: map[string]int{}}
				rows[key], order = row, append(order, key)
			}
			row.Critical = row.Critical || c.Critical
			cell := row.Cells[x.Kind]
			cell.ComponentID = c.ID
			if s, ok := compStates[c.ID]; ok {
				cell.Hosts += s.Hosts
				row.Color = worse(row.Color, s.Color)
				for k, v := range s.Problems {
					row.Problems[k] += v
				}
			}
			row.Cells[x.Kind] = cell
		}
	}
	for _, k := range order {
		out.Matrix = append(out.Matrix, *rows[k])
	}
	if e = tx.QueryRow(ctx, `SELECT count(DISTINCT a.site_id) FROM cmdb.bindings b JOIN assets.assets a ON a.tenant_id=b.tenant_id AND a.asset_uid=b.asset_uid
WHERE b.tenant_id=$1 AND b.component_id=ANY($2::uuid[]) AND b.valid_to IS NULL AND b.status='active'`, id.TenantID, compIDs).Scan(&out.Sites); e != nil {
		return out, e
	}
	if out.Attention, e = r.rsmAttention(ctx, tx, id.TenantID, compIDs, comps, envByID); e != nil {
		return out, e
	}
	rels, e := r.CMDB.RelationsOf(ctx, tx, id.TenantID, cmdb.End{Kind: "service", ID: uid})
	if e != nil {
		return out, e
	}
	for _, rel := range rels {
		if rel.Type != "depends_on" || rel.From.Kind != "service" || rel.To.Kind != "service" {
			continue
		}
		other, mine := rel.To.ID, true
		if rel.To.ID == uid {
			other, mine = rel.From.ID, false
		}
		d := RSMDependency{UID: other, Color: "grey", Problems: map[string]int{}}
		if tx.QueryRow(ctx, `SELECT s.name,s.criticality,COALESCE(ns.color,'grey'),COALESCE(ns.problems,'{}'::jsonb) FROM cmdb.services s
LEFT JOIN cmdb.node_states ns ON ns.tenant_id=s.tenant_id AND ns.node_kind='system' AND ns.node_id=s.service_uid WHERE s.tenant_id=$1 AND s.service_uid=$2 AND s.retired_at IS NULL`, id.TenantID, other).Scan(&d.Name, &d.Criticality, &d.Color, &d.Problems) != nil {
			continue
		}
		if mine {
			out.DependsOn = append(out.DependsOn, d)
		} else {
			out.Dependents = append(out.Dependents, d)
		}
	}
	if out.Changes, out.ChangesTotal, e = r.rsmChanges(ctx, tx, id.TenantID, uid, envIDs, compIDs, 7); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

// rsmAttention — проблемные хосты системы, сгруппированные по (компонент, среда, первая причина); до 20 групп.
func (r *Registry) rsmAttention(ctx context.Context, tx pgx.Tx, tenant string, compIDs []string, comps map[string][]cmdb.Component, envs map[string]cmdb.Environment) ([]RSMAttention, error) {
	out := []RSMAttention{}
	if len(compIDs) == 0 {
		return out, nil
	}
	compByID := map[string]cmdb.Component{}
	for _, list := range comps {
		for _, c := range list {
			compByID[c.ID] = c
		}
	}
	rows, e := tx.Query(ctx, `SELECT b.component_id::text,b.asset_uid::text,h.color,h.reasons FROM cmdb.bindings b JOIN cmdb.host_states h ON h.tenant_id=b.tenant_id AND h.asset_uid=b.asset_uid
WHERE b.tenant_id=$1 AND b.component_id=ANY($2::uuid[]) AND b.valid_to IS NULL AND b.status='active' AND h.color IN ('red','yellow')
ORDER BY CASE h.color WHEN 'red' THEN 0 ELSE 1 END,b.asset_uid LIMIT 5000`, tenant, compIDs)
	if e != nil {
		return nil, e
	}
	groups := map[string]*RSMAttention{}
	keys := []string{}
	uids := []string{}
	for rows.Next() {
		var comp, asset, color string
		var raw []byte
		if e = rows.Scan(&comp, &asset, &color, &raw); e != nil {
			rows.Close()
			return nil, e
		}
		var reasons []RSMReason
		_ = json.Unmarshal(raw, &reasons)
		code, detail := "", ""
		if len(reasons) > 0 {
			code, detail = reasons[0].Code, reasons[0].Detail
			if strings.HasPrefix(code, "INVENTORY_") || code == "NO_INVENTORY" {
				detail = "" // даты у хостов разные — группа по причине
			}
		}
		c := compByID[comp]
		key := comp + "|" + code + "|" + detail
		g := groups[key]
		if g == nil {
			g = &RSMAttention{Color: color, Code: code, Detail: detail, Component: c.Name, ComponentID: comp, Environment: envs[c.EnvironmentID].Name, Hosts: []RSMAssetRef{}}
			groups[key], keys = g, append(keys, key)
		}
		g.Total++
		if color == "red" {
			g.Color = "red"
		}
		if len(g.Hosts) < 5 {
			g.Hosts = append(g.Hosts, RSMAssetRef{AssetUID: asset})
			uids = append(uids, asset)
		}
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return nil, e
	}
	names, e := rsmNames(ctx, tx, tenant, uids)
	if e != nil {
		return nil, e
	}
	for _, k := range keys {
		g := groups[k]
		for i := range g.Hosts {
			g.Hosts[i].Name = names[g.Hosts[i].AssetUID]
		}
		out = append(out, *g)
		if len(out) == 20 {
			break
		}
	}
	return out, nil
}

// rsmChanges — изменения за days дней: история cmdb (система, среды, компоненты, привязки и правила компонентов) и
// история активов системы (без проекций описи); новые сверху, до 50; total — всего за период.
func (r *Registry) rsmChanges(ctx context.Context, tx pgx.Tx, tenant, system string, envIDs, compIDs []string, days int) ([]RSMChange, int, error) {
	out := []RSMChange{}
	ids := append(append([]string{system}, envIDs...), compIDs...)
	const q = `WITH binds AS (SELECT binding_id,asset_uid FROM cmdb.bindings WHERE tenant_id=$1 AND component_id=ANY($3::uuid[])),
rules AS (SELECT rule_id FROM cmdb.binding_rules WHERE tenant_id=$1 AND component_id=ANY($3::uuid[])),
hosts AS (SELECT DISTINCT asset_uid FROM binds),
x AS (
 SELECT c.occurred_at,'cmdb' AS source,c.object_type,c.action,c.detail,COALESCE((SELECT b.asset_uid FROM binds b WHERE b.binding_id=c.object_id),(CASE WHEN c.detail ? 'asset_uid' THEN (c.detail->>'asset_uid')::uuid END)) AS asset_uid
 FROM cmdb.changes c WHERE c.tenant_id=$1 AND c.occurred_at>now()-make_interval(days=>$4) AND (c.object_id=ANY($2::uuid[]) OR c.object_id IN (SELECT binding_id FROM binds) OR c.object_id IN (SELECT rule_id FROM rules))
 UNION ALL
 SELECT a.occurred_at,'asset',a.reason_code,'',a.provenance,a.asset_uid FROM assets.asset_changes a
 WHERE a.tenant_id=$1 AND a.asset_uid IN (SELECT asset_uid FROM hosts) AND a.occurred_at>now()-make_interval(days=>$4) AND a.reason_code NOT IN ('INVENTORY_PROJECTED','TEST_PROJECTION'))
SELECT occurred_at,source,object_type,action,detail,asset_uid::text,count(*) OVER () FROM x ORDER BY occurred_at DESC LIMIT 50`
	rows, e := tx.Query(ctx, q, tenant, ids, compIDs, days)
	if e != nil {
		return nil, 0, e
	}
	total := 0
	uids := []string{}
	for rows.Next() {
		var c RSMChange
		if e = rows.Scan(&c.At, &c.Source, &c.Object, &c.Action, &c.Detail, &c.AssetUID, &total); e != nil {
			rows.Close()
			return nil, 0, e
		}
		c.At = c.At.UTC()
		if c.AssetUID != nil {
			uids = append(uids, *c.AssetUID)
		}
		out = append(out, c)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return nil, 0, e
	}
	names, e := rsmNames(ctx, tx, tenant, uids)
	if e != nil {
		return nil, 0, e
	}
	for i := range out {
		if out[i].AssetUID != nil {
			out[i].AssetName = names[*out[i].AssetUID]
		}
	}
	return out, total, nil
}

// --- карточка компонента ---

type RSMCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type RSMBaselineItem struct {
	Key        string     `json:"key"` // os | software:<имя>
	Label      string     `json:"label"`
	Expected   string     `json:"expected"`
	Values     []RSMCount `json:"values"` // наблюдаемые значения (до 5) с числом хостов
	Deviations int        `json:"deviations"`
	NoData     int        `json:"no_data"`
}

type RSMComponentHost struct {
	RSMHostRow
	IP     string            `json:"ip"`
	Site   string            `json:"site"`
	Values map[string]string `json:"values"` // ключ эталона → наблюдаемое значение («» — нет)
}

type RSMComponentCard struct {
	RSMComponentDetail
	Hosts         []RSMComponentHost `json:"hosts"`
	SystemUID     string             `json:"service_uid"`
	ITSubjectName *string            `json:"it_subject_name"`
	Sites         []RSMCount         `json:"sites"`
	Networks      []RSMCount         `json:"networks"`
	Baseline      []RSMBaselineItem  `json:"baseline_summary"`
	Matched       int                `json:"matched"` // хостов под фильтром
}

type baselineSpec struct {
	OS       string            `json:"os"`
	Software map[string]string `json:"software"`
}

// RSMComponentCard — карточка компонента: строки хостов под фильтром (q — имя или IP, site — имя площадки, color — цвет),
// сводка эталона по всем хостам компонента.
func (r *Registry) RSMComponentCard(ctx context.Context, id accessport.Identity, component, q, site, color string, offset, limit int) (RSMComponentCard, error) {
	out := RSMComponentCard{Hosts: []RSMComponentHost{}, Sites: []RSMCount{}, Networks: []RSMCount{}, Baseline: []RSMBaselineItem{}}
	q = strings.ToLower(strings.TrimSpace(q))
	if len(q) > 128 || len(site) > 512 || (color != "" && color != "red" && color != "yellow" && color != "green" && color != "grey") {
		return out, domain.Invalid
	}
	base, e := r.RSMComponent(ctx, id, component, 0, 1)
	if e != nil {
		return out, e
	}
	out.RSMComponentDetail = base
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	out.SystemUID = base.Environment.ServiceUID
	if e = tx.QueryRow(ctx, "SELECT (SELECT name FROM responsibility.subjects x WHERE x.tenant_id=s.tenant_id AND x.subject_id=s.it_subject_id) FROM cmdb.services s WHERE s.tenant_id=$1 AND s.service_uid=$2", id.TenantID, out.SystemUID).Scan(&out.ITSubjectName); e != nil {
		return out, e
	}
	// все хосты компонента: площадка, адрес, цвет
	rows, e := tx.Query(ctx, `SELECT b.asset_uid::text,COALESCE(st.name,''),a.site_id::text,COALESCE(h.color,'grey'),COALESCE(h.reasons,'[]'::jsonb),h.last_inventory_at,b.binding_id::text,b.is_primary,b.origin
FROM cmdb.bindings b JOIN assets.assets a ON a.tenant_id=b.tenant_id AND a.asset_uid=b.asset_uid LEFT JOIN scope.sites st ON st.tenant_id=a.tenant_id AND st.site_id=a.site_id
LEFT JOIN cmdb.host_states h ON h.tenant_id=b.tenant_id AND h.asset_uid=b.asset_uid
WHERE b.tenant_id=$1 AND b.component_id=$2 AND b.valid_to IS NULL AND b.status='active'
ORDER BY CASE COALESCE(h.color,'grey') WHEN 'red' THEN 0 WHEN 'yellow' THEN 1 WHEN 'grey' THEN 2 ELSE 3 END,b.asset_uid LIMIT 20000`, id.TenantID, component)
	if e != nil {
		return out, e
	}
	type hostRow struct {
		RSMComponentHost
		siteID string
	}
	all := []hostRow{}
	uids := []string{}
	for rows.Next() {
		var h hostRow
		if e = rows.Scan(&h.AssetUID, &h.Site, &h.siteID, &h.Color, &h.Reasons, &h.LastInventory, &h.BindingID, &h.Primary, &h.Origin); e != nil {
			rows.Close()
			return out, e
		}
		all = append(all, h)
		uids = append(uids, h.AssetUID)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return out, e
	}
	ips, e := rsmIPs(ctx, tx, id.TenantID, uids)
	if e != nil {
		return out, e
	}
	names, e := rsmNames(ctx, tx, id.TenantID, uids)
	if e != nil {
		return out, e
	}
	// эталон: значения ОС и версий ПО по каждому хосту
	var spec baselineSpec
	_ = json.Unmarshal(base.Component.Baseline, &spec)
	values := map[string]map[string]string{} // хост → ключ → значение
	if spec.OS != "" || len(spec.Software) > 0 {
		// ОС — как в карточке актива (профили 1.0 и 1.2), пачками по 1000
		for k := 0; k < len(uids); k += 1000 {
			batch := uids[k:min(k+1000, len(uids))]
			list := make([]*contracts.Asset, len(batch))
			for n, u := range batch {
				list[n] = &contracts.Asset{TenantID: id.TenantID, UID: u}
			}
			if e = r.Inventory.EnrichMany(ctx, tx, list); e != nil {
				return out, e
			}
			for _, a := range list {
				if a.OS != nil {
					if values[a.UID] == nil {
						values[a.UID] = map[string]string{}
					}
					values[a.UID]["os"] = *a.OS
				}
			}
		}
		if len(spec.Software) > 0 {
			sw, e := rsmSoftware(ctx, tx, id.TenantID, uids)
			if e != nil {
				return out, e
			}
			for u, list := range sw {
				for name := range spec.Software {
					needle := strings.ToLower(name)
					for n, versions := range list {
						if strings.Contains(n, needle) {
							if values[u] == nil {
								values[u] = map[string]string{}
							}
							v := strings.Join(versions, ", ")
							if v == "" {
								v = "есть"
							}
							values[u]["software:"+name] = v
						}
					}
				}
				if values[u] == nil {
					values[u] = map[string]string{}
				}
				values[u]["_software"] = "1" // ПО собрано — отсутствие пакета значимо
			}
		}
	}
	// сводка эталона
	if spec.OS != "" {
		out.Baseline = append(out.Baseline, baselineItem("os", "ОС", spec.OS, uids, values, func(have, want string) bool { return strings.Contains(strings.ToLower(have), strings.ToLower(want)) }, false))
	}
	swNames := make([]string, 0, len(spec.Software))
	for n := range spec.Software {
		swNames = append(swNames, n)
	}
	sort.Strings(swNames)
	for _, n := range swNames {
		want := spec.Software[n]
		out.Baseline = append(out.Baseline, baselineItem("software:"+n, n, want, uids, values, func(have, w string) bool {
			if w == "" {
				return have != ""
			}
			for _, v := range strings.Split(have, ", ") {
				if strings.HasPrefix(v, w) {
					return true
				}
			}
			return false
		}, true))
	}
	// площадки и сети /24 по всем хостам
	sites, nets := map[string]int{}, map[string]int{}
	for _, h := range all {
		sites[h.Site]++
		if a, err := netip.ParseAddr(ips[h.AssetUID]); err == nil && a.Is4() {
			p, _ := a.Prefix(24)
			nets[p.String()]++
		}
	}
	out.Sites, out.Networks = topCounts(sites, 6), topCounts(nets, 4)
	// фильтр строк
	filtered := []RSMComponentHost{}
	for _, h := range all {
		name := names[h.AssetUID]
		if q != "" && !strings.Contains(strings.ToLower(name), q) && !strings.Contains(ips[h.AssetUID], q) {
			continue
		}
		if site != "" && h.Site != site {
			continue
		}
		if color != "" && h.Color != color {
			continue
		}
		row := h.RSMComponentHost
		row.Name, row.IP, row.Values = name, ips[h.AssetUID], map[string]string{}
		for k, v := range values[h.AssetUID] {
			if !strings.HasPrefix(k, "_") {
				row.Values[k] = v
			}
		}
		filtered = append(filtered, row)
	}
	out.Matched = len(filtered)
	if offset > len(filtered) {
		offset = len(filtered)
	}
	end := min(offset+limit, len(filtered))
	out.Hosts, out.Offset = filtered[offset:end], offset
	out.NextOffset = nil
	if end < len(filtered) {
		next := end
		out.NextOffset = &next
	}
	out.RSMComponentDetail.Hosts = nil
	return out, tx.Commit(ctx)
}

func baselineItem(key, label, want string, uids []string, values map[string]map[string]string, ok func(have, want string) bool, software bool) RSMBaselineItem {
	it := RSMBaselineItem{Key: key, Label: label, Expected: want, Values: []RSMCount{}}
	counts := map[string]int{}
	for _, u := range uids {
		v := values[u]
		have, known := v[key]
		if software && !known && v["_software"] != "" {
			have, known = "нет", true // ПО собрано, пакета нет
		}
		if !known {
			it.NoData++
			continue
		}
		counts[have]++
		if have == "нет" || !ok(have, want) {
			it.Deviations++
		}
	}
	it.Values = topCounts(counts, 5)
	return it
}

func topCounts(m map[string]int, n int) []RSMCount {
	out := make([]RSMCount, 0, len(m))
	for k, v := range m {
		out = append(out, RSMCount{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}
