package app

// C54.03 — состояние РСМ (светофор) до мониторинга метрик (C55). Цвет хоста — из того, что уже собирается:
// свежесть инвентаризации, присутствие в подсети (C21), отклонение от эталона компонента, открытые конфликты
// сопоставления. Подъём: хост → компонент (доля красных) → среда (критичный компонент — сразу) → система (непрод-
// среды не красят систему в красный) → направление и компания (красной делают только системы высокой/критической
// важности). Пересчёт — фоновой задачей раз в 5 минут (и по запросу); чтение дерева — из готовых агрегатов.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/cmdb"
	"github.com/jackc/pgx/v5"
)

const (
	rsmStaleAfter = 24 * time.Hour     // жёлтый: инвентаризация старше суток
	rsmLostAfter  = 7 * 24 * time.Hour // красный: старше недели
	rsmBatch      = 1000
)

// RSMReason — «почему такой цвет»: код, ссылка на узел (компонент/среда/система), число и подробность.
type RSMReason struct {
	Code   string `json:"code"`
	Ref    string `json:"ref,omitempty"`
	Name   string `json:"name,omitempty"`
	Count  int    `json:"count,omitempty"`
	Detail string `json:"detail,omitempty"`
}

var colorWeight = map[string]int{"grey": 0, "green": 1, "yellow": 2, "red": 3}

func worse(a, b string) string {
	if colorWeight[b] > colorWeight[a] {
		return b
	}
	return a
}

// hostInput — данные одного хоста для цвета.
type hostInput struct {
	LastInventory *time.Time
	Presence      string // present | missing | unknown
	Conflicts     int
	Deviations    []RSMReason
}

func hostColor(in hostInput, now time.Time) (string, []RSMReason) {
	color, reasons := "green", []RSMReason{}
	if in.Presence == "missing" {
		color, reasons = "red", append(reasons, RSMReason{Code: "HOST_MISSING", Detail: "не найден полными обследованиями подсети"})
	}
	switch {
	case in.LastInventory == nil:
		if color != "red" {
			color = "grey"
		}
		reasons = append(reasons, RSMReason{Code: "NO_INVENTORY"})
	case now.Sub(*in.LastInventory) > rsmLostAfter:
		color = "red"
		reasons = append(reasons, RSMReason{Code: "INVENTORY_LOST", Detail: in.LastInventory.UTC().Format(time.RFC3339)})
	case now.Sub(*in.LastInventory) > rsmStaleAfter:
		color = worse(color, "yellow")
		reasons = append(reasons, RSMReason{Code: "INVENTORY_STALE", Detail: in.LastInventory.UTC().Format(time.RFC3339)})
	}
	if in.Conflicts > 0 {
		color = worse(color, "yellow")
		reasons = append(reasons, RSMReason{Code: "RECONCILIATION_CONFLICT", Count: in.Conflicts})
	}
	if len(in.Deviations) > 0 {
		color = worse(color, "yellow")
		reasons = append(reasons, in.Deviations...)
	}
	return color, reasons
}

// hostSoftware — ПО хоста: название (нижний регистр) → версии.
type hostSoftware map[string][]string

// baselineDeviations сверяет хост с эталоном компонента. Проверяются os (подстрока observed OS) и software
// (название — подстрока, версия — префикс). Нет данных хоста (ОС/ПО не собраны) — пункт не проверяется: отсутствие
// данных не выдаётся за отклонение. Прочие ключи эталона (антивирус, порты, админы) — до появления данных (C55).
func baselineDeviations(component cmdb.TopologyComponent, os *string, sw hostSoftware) []RSMReason {
	if len(component.Baseline) == 0 {
		return nil
	}
	var b struct {
		OS       string            `json:"os"`
		Software map[string]string `json:"software"`
	}
	if json.Unmarshal(component.Baseline, &b) != nil {
		return nil
	}
	var out []RSMReason
	if b.OS != "" && os != nil && !strings.Contains(strings.ToLower(*os), strings.ToLower(b.OS)) {
		out = append(out, RSMReason{Code: "BASELINE_OS", Ref: component.ID, Name: component.Name, Detail: *os + " ≠ " + b.OS})
	}
	if len(sw) > 0 {
		names := make([]string, 0, len(b.Software))
		for n := range b.Software {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			want, needle := b.Software[name], strings.ToLower(name)
			found, versionOK, have := false, want == "", ""
			for n, versions := range sw {
				if !strings.Contains(n, needle) {
					continue
				}
				found = true
				for _, v := range versions {
					have = v
					if want != "" && strings.HasPrefix(v, want) {
						versionOK = true
					}
				}
			}
			switch {
			case !found:
				out = append(out, RSMReason{Code: "BASELINE_SOFTWARE_MISSING", Ref: component.ID, Name: component.Name, Detail: name})
			case !versionOK:
				out = append(out, RSMReason{Code: "BASELINE_SOFTWARE_VERSION", Ref: component.ID, Name: component.Name, Detail: name + ": " + have + " ≠ " + want})
			}
		}
	}
	return out
}

func raw(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// count — разбивка множества хостов по цветам.
func count(hosts map[string]bool, colors map[string]string) (n cmdb.NodeState) {
	for h := range hosts {
		n.Hosts++
		switch colors[h] {
		case "green":
			n.Green++
		case "yellow":
			n.Yellow++
		case "red":
			n.Red++
		default:
			n.Grey++
		}
	}
	return n
}

// rollupRSM — подъём цвета по дереву. colors — цвет каждого привязанного хоста.
func rollupRSM(t cmdb.Topology, colors map[string]string, unassigned int) []cmdb.NodeState {
	out := []cmdb.NodeState{}
	envComponents := map[string][]cmdb.TopologyComponent{}
	for _, c := range t.Components {
		envComponents[c.Environment] = append(envComponents[c.Environment], c)
	}
	componentColor, componentHosts := map[string]string{}, map[string]map[string]bool{}
	for _, c := range t.Components {
		set := map[string]bool{}
		for _, h := range t.Bindings[c.ID] {
			set[h] = true
		}
		componentHosts[c.ID] = set
		n := count(set, colors)
		n.Kind, n.ID = "component", c.ID
		reasons := []RSMReason{}
		switch {
		case n.Hosts == 0:
			n.Color, reasons = "grey", append(reasons, RSMReason{Code: "NO_HOSTS"})
		case n.Grey == n.Hosts:
			n.Color, reasons = "grey", append(reasons, RSMReason{Code: "NO_DATA", Count: n.Grey})
		case n.Red*2 >= n.Hosts:
			n.Color = "red"
		case n.Red > 0 || n.Yellow > 0:
			n.Color = "yellow"
		default:
			n.Color = "green"
		}
		if n.Red > 0 {
			reasons = append(reasons, RSMReason{Code: "HOSTS_RED", Count: n.Red, Detail: fmt.Sprintf("%d из %d", n.Red, n.Hosts)})
		}
		if n.Yellow > 0 {
			reasons = append(reasons, RSMReason{Code: "HOSTS_YELLOW", Count: n.Yellow})
		}
		if n.Grey > 0 && n.Grey < n.Hosts {
			reasons = append(reasons, RSMReason{Code: "HOSTS_NO_DATA", Count: n.Grey})
		}
		n.Reasons = raw(reasons)
		componentColor[c.ID] = n.Color
		out = append(out, n)
	}
	envColor, envHosts := map[string]string{}, map[string]map[string]bool{}
	systemEnvs := map[string][]cmdb.TopologyEnvironment{}
	for _, e := range t.Environments {
		systemEnvs[e.Service] = append(systemEnvs[e.Service], e)
		set, reasons, color, any := map[string]bool{}, []RSMReason{}, "grey", false
		for _, c := range envComponents[e.ID] {
			for h := range componentHosts[c.ID] {
				set[h] = true
			}
			cc := componentColor[c.ID]
			switch {
			case cc == "red" && c.Critical:
				color, reasons = worse(color, "red"), append(reasons, RSMReason{Code: "CRITICAL_COMPONENT_RED", Ref: c.ID, Name: c.Name})
			case cc == "red":
				color, reasons = worse(color, "yellow"), append(reasons, RSMReason{Code: "COMPONENT_RED", Ref: c.ID, Name: c.Name})
			case cc == "yellow":
				color, reasons = worse(color, "yellow"), append(reasons, RSMReason{Code: "COMPONENT_YELLOW", Ref: c.ID, Name: c.Name})
			case cc == "green":
				color = worse(color, "green")
			}
			any = true
		}
		if !any {
			reasons = append(reasons, RSMReason{Code: "NO_COMPONENTS"})
		}
		n := count(set, colors)
		n.Kind, n.ID, n.Color, n.Reasons = "environment", e.ID, color, raw(reasons)
		envColor[e.ID], envHosts[e.ID] = color, set
		out = append(out, n)
	}
	systemColor, systemHosts := map[string]string{}, map[string]map[string]bool{}
	for _, s := range t.Systems {
		set, reasons, color := map[string]bool{}, []RSMReason{}, "grey"
		for _, e := range systemEnvs[s.UID] {
			for h := range envHosts[e.ID] {
				set[h] = true
			}
			ec := envColor[e.ID]
			production := e.Kind == "prod" || e.Kind == "dr"
			switch {
			case ec == "red" && production:
				color, reasons = worse(color, "red"), append(reasons, RSMReason{Code: "ENVIRONMENT_RED", Ref: e.ID, Name: e.Name})
			case ec == "red":
				color, reasons = worse(color, "yellow"), append(reasons, RSMReason{Code: "NONPROD_ENVIRONMENT_RED", Ref: e.ID, Name: e.Name})
			case ec == "yellow":
				color, reasons = worse(color, "yellow"), append(reasons, RSMReason{Code: "ENVIRONMENT_YELLOW", Ref: e.ID, Name: e.Name})
			case ec == "green":
				color = worse(color, "green")
			}
		}
		if len(systemEnvs[s.UID]) == 0 {
			reasons = append(reasons, RSMReason{Code: "NO_ENVIRONMENTS"})
		}
		n := count(set, colors)
		n.Kind, n.ID, n.Color, n.Reasons = "system", s.UID, color, raw(reasons)
		systemColor[s.UID], systemHosts[s.UID] = color, set
		out = append(out, n)
	}
	// направление и компания: красная система высокой/критической важности — красный, иначе — жёлтый
	group := func(kind, id string, systems []cmdb.TopologySystem, unassigned int) cmdb.NodeState {
		set, reasons, color := map[string]bool{}, []RSMReason{}, "grey"
		for _, s := range systems {
			for h := range systemHosts[s.UID] {
				set[h] = true
			}
			sc := systemColor[s.UID]
			important := s.Criticality == "high" || s.Criticality == "critical"
			switch {
			case sc == "red" && important:
				color, reasons = worse(color, "red"), append(reasons, RSMReason{Code: "CRITICAL_SYSTEM_RED", Ref: s.UID, Name: s.Name})
			case sc == "red":
				color, reasons = worse(color, "yellow"), append(reasons, RSMReason{Code: "SYSTEM_RED", Ref: s.UID, Name: s.Name})
			case sc == "yellow":
				color, reasons = worse(color, "yellow"), append(reasons, RSMReason{Code: "SYSTEM_YELLOW", Ref: s.UID, Name: s.Name})
			case sc == "green":
				color = worse(color, "green")
			}
		}
		if len(reasons) > 50 { // компания на тысячах систем: в «почему» — первые 50, полный список — в списке систем
			reasons = append(reasons[:50], RSMReason{Code: "MORE", Count: len(reasons) - 50})
		}
		if unassigned > 0 {
			reasons = append(reasons, RSMReason{Code: "UNASSIGNED_HOSTS", Count: unassigned})
		}
		n := count(set, colors)
		n.Kind, n.ID, n.Color, n.Reasons, n.Unassigned = kind, id, color, raw(reasons), unassigned
		return n
	}
	byDirection := map[string][]cmdb.TopologySystem{}
	for _, s := range t.Systems {
		if s.Direction != nil {
			byDirection[*s.Direction] = append(byDirection[*s.Direction], s)
		}
	}
	for _, d := range t.Directions {
		out = append(out, group("direction", d, byDirection[d], 0))
	}
	return append(out, group("tenant", "", t.Systems, unassigned))
}

// RSMStateResult — итог пересчёта.
type RSMStateResult struct {
	Hosts    int                      `json:"hosts"`
	Nodes    int                      `json:"nodes"`
	Skipped  bool                     `json:"skipped"` // пересчёт уже идёт в другом процессе
	Duration time.Duration            `json:"duration_ns"`
	Phases   map[string]time.Duration `json:"phases_ns"` // время по фазам (паспорт нагрузки)
}

// RecomputeRSMState пересчитывает состояние РСМ тенанта: чтение — пачками по 1000 хостов, запись — одной транзакцией
// под advisory-блокировкой тенанта (второй процесс того же тенанта пропускает проход).
func (r *Registry) RecomputeRSMState(ctx context.Context, tenant string) (RSMStateResult, error) {
	started := time.Now()
	out := RSMStateResult{Phases: map[string]time.Duration{}}
	mark := time.Now()
	phase := func(name string) { out.Phases[name] += time.Since(mark); mark = time.Now() }
	read, e := r.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if e != nil {
		return out, e
	}
	defer read.Rollback(ctx)
	topo, e := r.CMDB.LoadTopology(ctx, read, tenant)
	if e != nil {
		return out, e
	}
	hostComponents := map[string][]cmdb.TopologyComponent{}
	byID := map[string]cmdb.TopologyComponent{}
	softwareNeeded := false
	for _, c := range topo.Components {
		byID[c.ID] = c
		if strings.Contains(string(c.Baseline), `"software"`) {
			softwareNeeded = true
		}
	}
	for comp, hosts := range topo.Bindings {
		for _, h := range hosts {
			if c, ok := byID[comp]; ok {
				hostComponents[h] = append(hostComponents[h], c)
			}
		}
	}
	uids := make([]string, 0, len(hostComponents))
	for h := range hostComponents {
		uids = append(uids, h)
	}
	sort.Strings(uids)
	now := time.Now().UTC()
	states := make([]cmdb.HostState, 0, len(uids))
	colors := make(map[string]string, len(uids))
	for i := 0; i < len(uids); i += rsmBatch {
		batch := uids[i:min(i+rsmBatch, len(uids))]
		list := make([]*contracts.Asset, len(batch))
		for k, uid := range batch {
			list[k] = &contracts.Asset{TenantID: tenant, UID: uid}
		}
		phase("other")
		if e = r.Inventory.EnrichMany(ctx, read, list); e != nil {
			return out, e
		}
		phase("inventory")
		presence, e := rsmPresence(ctx, read, tenant, batch)
		if e != nil {
			return out, e
		}
		phase("presence")
		conflicts, e := rsmConflicts(ctx, read, tenant, batch)
		if e != nil {
			return out, e
		}
		phase("conflicts")
		software := map[string]hostSoftware{}
		if softwareNeeded {
			if software, e = rsmSoftware(ctx, read, tenant, batch); e != nil {
				return out, e
			}
		}
		for _, a := range list {
			var dev []RSMReason
			for _, c := range hostComponents[a.UID] {
				dev = append(dev, baselineDeviations(c, a.OS, software[a.UID])...)
			}
			p := presence[a.UID]
			if p == "" {
				p = "unknown"
			}
			color, reasons := hostColor(hostInput{LastInventory: a.LastInventory, Presence: p, Conflicts: conflicts[a.UID], Deviations: dev}, now)
			colors[a.UID] = color
			states = append(states, cmdb.HostState{AssetUID: a.UID, Color: color, Reasons: raw(reasons), LastInventory: a.LastInventory})
		}
	}
	phase("hosts")
	unassigned, e := r.CMDB.UnassignedCount(ctx, read, tenant)
	if e != nil {
		return out, e
	}
	phase("unassigned")
	read.Rollback(ctx)
	nodes := rollupRSM(topo, colors, unassigned)
	for k := range nodes {
		if nodes[k].Kind == "tenant" {
			nodes[k].ID = tenant
		}
	}
	write, e := r.Pool.Begin(ctx)
	if e != nil {
		return out, e
	}
	defer write.Rollback(ctx)
	var locked bool
	if e = write.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock(hashtextextended('rsm_state:'||$1::text,0))", tenant).Scan(&locked); e != nil {
		return out, e
	}
	if !locked {
		out.Skipped = true
		return out, nil
	}
	for i := 0; i < len(states); i += 5000 {
		if e = r.CMDB.SaveHostStates(ctx, write, tenant, states[i:min(i+5000, len(states))], now); e != nil {
			return out, e
		}
	}
	if e = r.CMDB.PruneHostStates(ctx, write, tenant, now); e != nil {
		return out, e
	}
	if e = r.CMDB.ReplaceNodeStates(ctx, write, tenant, nodes, now); e != nil {
		return out, e
	}
	if e = write.Commit(ctx); e != nil {
		return out, e
	}
	phase("write")
	out.Hosts, out.Nodes, out.Duration = len(states), len(nodes), time.Since(started)
	return out, nil
}

// rsmPresence — присутствие хостов по обследованиям подсетей (C21): на месте, если найден хоть один адрес; пропал —
// если найденные ранее адреса все пропали; адреса не в обследуемых подсетях — нет сведений.
func rsmPresence(ctx context.Context, tx pgx.Tx, tenant string, uids []string) (map[string]string, error) {
	rows, e := tx.Query(ctx, `WITH ips AS (
SELECT asset_uid,jsonb_array_elements(value)->>'ip' AS ip FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=ANY($2::uuid[]) AND section_name='network' AND field_name='addresses' AND jsonb_typeof(value)='array'
UNION SELECT asset_uid,jsonb_array_elements(value::jsonb)->>'ip' FROM inventory.current_facts WHERE tenant_id=$1 AND asset_uid=ANY($2::uuid[]) AND section_name='network' AND fact_key LIKE '%.addresses')
SELECT i.asset_uid::text,bool_or(d.state='present') FROM ips i JOIN sources.discovery_hosts d ON d.tenant_id=$1 AND host(d.ip)=i.ip GROUP BY 1`, tenant, uids)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var uid string
		var present bool
		if e = rows.Scan(&uid, &present); e != nil {
			return nil, e
		}
		out[uid] = map[bool]string{true: "present", false: "missing"}[present]
	}
	return out, rows.Err()
}

func rsmConflicts(ctx context.Context, tx pgx.Tx, tenant string, uids []string) (map[string]int, error) {
	rows, e := tx.Query(ctx, `SELECT u::text,count(*) FROM assets.reconciliation_conflicts c CROSS JOIN LATERAL unnest(c.candidate_asset_uids) u
WHERE c.tenant_id=$1 AND c.state='open' AND c.candidate_asset_uids && $2::uuid[] AND u=ANY($2::uuid[]) GROUP BY 1`, tenant, uids)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var uid string
		var n int
		if e = rows.Scan(&uid, &n); e != nil {
			return nil, e
		}
		out[uid] = n
	}
	return out, rows.Err()
}

func rsmSoftware(ctx context.Context, tx pgx.Tx, tenant string, uids []string) (map[string]hostSoftware, error) {
	rows, e := tx.Query(ctx, `SELECT n.asset_uid::text,lower(n.value #>> '{}'),COALESCE(v.value #>> '{}','') FROM inventory.record_facts12 n
LEFT JOIN inventory.record_facts12 v ON v.tenant_id=n.tenant_id AND v.asset_uid=n.asset_uid AND v.section_name='software' AND v.record_key=n.record_key AND v.field_name='version'
WHERE n.tenant_id=$1 AND n.asset_uid=ANY($2::uuid[]) AND n.section_name='software' AND n.field_name='name' AND jsonb_typeof(n.value)='string'`, tenant, uids)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := map[string]hostSoftware{}
	for rows.Next() {
		var uid, name, version string
		if e = rows.Scan(&uid, &name, &version); e != nil {
			return nil, e
		}
		if out[uid] == nil {
			out[uid] = hostSoftware{}
		}
		out[uid][name] = append(out[uid][name], version)
	}
	return out, rows.Err()
}

// RSMStateMaintain — раз в 5 минут пересчитывает состояние РСМ тенантов, где есть компоненты.
func (r *Registry) RSMStateMaintain(ctx context.Context, log func(string)) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		task, done := context.WithTimeout(ctx, 4*time.Minute)
		var tenants []string
		rows, e := r.Pool.Query(task, "SELECT DISTINCT tenant_id::text FROM cmdb.components WHERE retired_at IS NULL")
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
			log("rsm state: tenants unavailable: " + e.Error())
		}
		for _, tenant := range tenants {
			if _, e := r.RecomputeRSMState(task, tenant); e != nil {
				log("rsm state recompute failed: " + e.Error())
			}
		}
		done()
	}
}
