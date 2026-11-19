package cmdb

// C54.03 — хранение и чтение состояния РСМ (светофор). Расчёт цвета — в слое app; модуль хранит результат
// (host_states, node_states) и отдаёт структуру дерева для подъёма цвета и страницы для Web.

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

type HostState struct {
	AssetUID      string          `json:"asset_uid"`
	Color         string          `json:"color"`
	Reasons       json.RawMessage `json:"reasons"`
	LastInventory *time.Time      `json:"last_inventory_at"`
	ComputedAt    time.Time       `json:"computed_at"`
}

type NodeState struct {
	Kind       string          `json:"node_kind"`
	ID         string          `json:"node_id"`
	Color      string          `json:"color"`
	Hosts      int             `json:"hosts"`
	Green      int             `json:"green"`
	Yellow     int             `json:"yellow"`
	Red        int             `json:"red"`
	Grey       int             `json:"grey"`
	Unassigned int             `json:"unassigned"`
	Fresh      int             `json:"fresh"`    // хостов с инвентаризацией не старше суток
	Problems   map[string]int  `json:"problems"` // хостов по видам проблем: stale, no_data, missing, baseline, conflict
	Reasons    json.RawMessage `json:"reasons"`
	ComputedAt time.Time       `json:"computed_at"`
}

// SaveHostStates записывает состояния пачки хостов (upsert одним запросом).
func (Store) SaveHostStates(ctx context.Context, tx pgx.Tx, tenant string, list []HostState, at time.Time) error {
	if len(list) == 0 {
		return nil
	}
	uids, colors, reasons, last := make([]string, len(list)), make([]string, len(list)), make([]string, len(list)), make([]*time.Time, len(list))
	for i, h := range list {
		uids[i], colors[i], reasons[i], last[i] = h.AssetUID, h.Color, string(h.Reasons), h.LastInventory
	}
	_, e := tx.Exec(ctx, `INSERT INTO cmdb.host_states(tenant_id,asset_uid,color,reasons,last_inventory_at,computed_at)
SELECT $1,u,c,r::jsonb,l,$6 FROM unnest($2::uuid[],$3::text[],$4::text[],$5::timestamptz[]) AS x(u,c,r,l)
ON CONFLICT (tenant_id,asset_uid) DO UPDATE SET color=EXCLUDED.color,reasons=EXCLUDED.reasons,last_inventory_at=EXCLUDED.last_inventory_at,computed_at=EXCLUDED.computed_at`,
		tenant, uids, colors, reasons, last, at)
	return e
}

// PruneHostStates удаляет состояния хостов, не попавших в проход (отвязаны или поглощены слиянием).
func (Store) PruneHostStates(ctx context.Context, tx pgx.Tx, tenant string, before time.Time) error {
	_, e := tx.Exec(ctx, "DELETE FROM cmdb.host_states WHERE tenant_id=$1 AND computed_at<$2", tenant, before)
	return e
}

// ReplaceNodeStates заменяет состояние всех узлов дерева тенанта одним набором.
func (Store) ReplaceNodeStates(ctx context.Context, tx pgx.Tx, tenant string, list []NodeState, at time.Time) error {
	if _, e := tx.Exec(ctx, "DELETE FROM cmdb.node_states WHERE tenant_id=$1", tenant); e != nil {
		return e
	}
	n := len(list)
	kinds, ids, colors, reasons, problems := make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	fresh := make([]int32, n)
	hosts, green, yellow, red, grey, unassigned := make([]int32, n), make([]int32, n), make([]int32, n), make([]int32, n), make([]int32, n), make([]int32, n)
	for i, s := range list {
		kinds[i], ids[i], colors[i], reasons[i] = s.Kind, s.ID, s.Color, string(s.Reasons)
		fresh[i] = int32(s.Fresh)
		if s.Problems == nil {
			problems[i] = "{}"
		} else {
			raw, e := json.Marshal(s.Problems)
			if e != nil {
				return e
			}
			problems[i] = string(raw)
		}
		hosts[i], green[i], yellow[i], red[i], grey[i], unassigned[i] = int32(s.Hosts), int32(s.Green), int32(s.Yellow), int32(s.Red), int32(s.Grey), int32(s.Unassigned)
	}
	_, e := tx.Exec(ctx, `INSERT INTO cmdb.node_states(tenant_id,node_kind,node_id,color,hosts,green,yellow,red,grey,unassigned,reasons,computed_at,fresh,problems)
SELECT $1,k,i,c,h,g,y,r,gr,u,re::jsonb,$12,f,p::jsonb FROM unnest($2::text[],$3::uuid[],$4::text[],$5::int[],$6::int[],$7::int[],$8::int[],$9::int[],$10::int[],$11::text[],$13::int[],$14::text[]) AS x(k,i,c,h,g,y,r,gr,u,re,f,p)`,
		tenant, kinds, ids, colors, hosts, green, yellow, red, grey, unassigned, reasons, at, fresh, problems)
	return e
}

// Topology — структура РСМ тенанта для подъёма цвета.
type TopologyComponent struct {
	ID, Environment, Name string
	Critical              bool
	Baseline              json.RawMessage
}
type TopologyEnvironment struct{ ID, Service, Kind, Name string }
type TopologySystem struct {
	UID, Name, Criticality string
	Direction              *string
}
type Topology struct {
	Components   []TopologyComponent
	Environments []TopologyEnvironment
	Systems      []TopologySystem
	Directions   []string
	Bindings     map[string][]string // компонент → действующие хосты
}

func (Store) LoadTopology(ctx context.Context, tx pgx.Tx, tenant string) (Topology, error) {
	t := Topology{Bindings: map[string][]string{}}
	rows, e := tx.Query(ctx, `SELECT c.component_id::text,c.environment_id::text,c.name,c.critical,c.baseline FROM cmdb.components c
JOIN cmdb.environments e ON e.tenant_id=c.tenant_id AND e.environment_id=c.environment_id AND e.retired_at IS NULL
JOIN cmdb.services s ON s.tenant_id=e.tenant_id AND s.service_uid=e.service_uid AND s.retired_at IS NULL
WHERE c.tenant_id=$1 AND c.retired_at IS NULL`, tenant)
	if e != nil {
		return t, e
	}
	for rows.Next() {
		var c TopologyComponent
		if e = rows.Scan(&c.ID, &c.Environment, &c.Name, &c.Critical, &c.Baseline); e != nil {
			rows.Close()
			return t, e
		}
		t.Components = append(t.Components, c)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return t, e
	}
	rows, e = tx.Query(ctx, "SELECT environment_id::text,service_uid::text,kind,name FROM cmdb.environments WHERE tenant_id=$1 AND retired_at IS NULL", tenant)
	if e != nil {
		return t, e
	}
	for rows.Next() {
		var x TopologyEnvironment
		if e = rows.Scan(&x.ID, &x.Service, &x.Kind, &x.Name); e != nil {
			rows.Close()
			return t, e
		}
		t.Environments = append(t.Environments, x)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return t, e
	}
	rows, e = tx.Query(ctx, "SELECT service_uid::text,name,criticality,direction_uid::text FROM cmdb.services WHERE tenant_id=$1 AND retired_at IS NULL", tenant)
	if e != nil {
		return t, e
	}
	for rows.Next() {
		var x TopologySystem
		if e = rows.Scan(&x.UID, &x.Name, &x.Criticality, &x.Direction); e != nil {
			rows.Close()
			return t, e
		}
		t.Systems = append(t.Systems, x)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return t, e
	}
	rows, e = tx.Query(ctx, "SELECT direction_uid::text FROM cmdb.directions WHERE tenant_id=$1 AND retired_at IS NULL", tenant)
	if e != nil {
		return t, e
	}
	for rows.Next() {
		var d string
		if e = rows.Scan(&d); e != nil {
			rows.Close()
			return t, e
		}
		t.Directions = append(t.Directions, d)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return t, e
	}
	rows, e = tx.Query(ctx, "SELECT component_id::text,asset_uid::text FROM cmdb.bindings WHERE tenant_id=$1 AND valid_to IS NULL AND status='active'", tenant)
	if e != nil {
		return t, e
	}
	defer rows.Close()
	for rows.Next() {
		var c, a string
		if e = rows.Scan(&c, &a); e != nil {
			return t, e
		}
		t.Bindings[c] = append(t.Bindings[c], a)
	}
	return t, rows.Err()
}

// UnassignedCount — действующие активы без действующей привязки («хосты вне систем»).
func (Store) UnassignedCount(ctx context.Context, tx pgx.Tx, tenant string) (int, error) {
	var n int
	// разность двух агрегатов вместо anti-join: план не зависит от статистики (на 100 000 хостов anti-join без
	// свежего ANALYZE уходил во вложенный цикл на секунды)
	e := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM assets.assets WHERE tenant_id=$1 AND merged_into IS NULL)
-(SELECT count(DISTINCT b.asset_uid) FROM cmdb.bindings b JOIN assets.assets a ON a.tenant_id=b.tenant_id AND a.asset_uid=b.asset_uid AND a.merged_into IS NULL
WHERE b.tenant_id=$1 AND b.valid_to IS NULL AND b.status='active')`, tenant).Scan(&n)
	return n, e
}

// UnassignedHosts — страница «хостов вне систем» (курсор — asset_uid).
func (Store) UnassignedHosts(ctx context.Context, tx pgx.Tx, tenant, after string, limit int) ([]string, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if after != "" && !identifier.Valid(after) {
		return nil, domain.Invalid
	}
	rows, e := tx.Query(ctx, `SELECT a.asset_uid::text FROM assets.assets a WHERE a.tenant_id=$1 AND a.merged_into IS NULL AND ($2='' OR a.asset_uid>$2::uuid)
AND NOT EXISTS(SELECT 1 FROM cmdb.bindings b WHERE b.tenant_id=a.tenant_id AND b.asset_uid=a.asset_uid AND b.valid_to IS NULL AND b.status='active')
ORDER BY a.asset_uid LIMIT $3`, tenant, after, limit)
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

func scanNode(r pgx.Row) (NodeState, error) {
	var s NodeState
	e := r.Scan(&s.Kind, &s.ID, &s.Color, &s.Hosts, &s.Green, &s.Yellow, &s.Red, &s.Grey, &s.Unassigned, &s.Reasons, &s.ComputedAt, &s.Fresh, &s.Problems)
	return s, e
}

// Node — состояние одного узла дерева; нет расчёта — NotFound.
func (Store) Node(ctx context.Context, tx pgx.Tx, tenant, kind, id string) (NodeState, error) {
	s, e := scanNode(tx.QueryRow(ctx, "SELECT node_kind,node_id::text,color,hosts,green,yellow,red,grey,unassigned,reasons,computed_at,fresh,problems FROM cmdb.node_states WHERE tenant_id=$1 AND node_kind=$2 AND node_id=$3", tenant, kind, id))
	if errors.Is(e, pgx.ErrNoRows) {
		return s, domain.NotFound
	}
	return s, e
}

// SystemState — строка списка систем с состоянием.
type SystemState struct {
	UID           string    `json:"service_uid"`
	Name          string    `json:"name"`
	Criticality   string    `json:"criticality"`
	Direction     *string   `json:"direction_uid"`
	BusinessOwner *string   `json:"business_owner"`
	State         NodeState `json:"state"`
}

// SystemFilter — фильтры списка систем (все — на сервере): цвет, важность (несколько), вид среды, направление
// ("none" — без направления), только с проблемами, только без владельца.
type SystemFilter struct {
	Color       string
	Criticality []string
	EnvKind     string
	Direction   string
	Problems    bool
	NoOwner     bool
	Offset      int
	Limit       int
}

func (f SystemFilter) valid() bool {
	for _, c := range f.Criticality {
		if !criticalities[c] {
			return false
		}
	}
	return f.Offset >= 0 && f.Offset <= 10000 && (f.Color == "" || f.Color == "red" || f.Color == "yellow" || f.Color == "green" || f.Color == "grey") &&
		(f.EnvKind == "" || environmentKinds[f.EnvKind]) && (f.Direction == "" || f.Direction == "none" || identifier.Valid(f.Direction))
}

// SystemsByState — страница систем: сначала проблемные, затем по имени; группировка по направлению делается в Web
// внутри страницы (страница до 500 систем).
func (Store) SystemsByState(ctx context.Context, tx pgx.Tx, tenant string, f SystemFilter) ([]SystemState, error) {
	if f.Limit <= 0 || f.Limit > 501 {
		f.Limit = 100
	}
	if !f.valid() {
		return nil, domain.Invalid
	}
	if f.Criticality == nil {
		f.Criticality = []string{}
	}
	rows, e := tx.Query(ctx, `SELECT s.service_uid::text,s.name,s.criticality,s.direction_uid::text,s.business_owner,
'system',s.service_uid::text,COALESCE(ns.color,'grey'),COALESCE(ns.hosts,0),COALESCE(ns.green,0),COALESCE(ns.yellow,0),COALESCE(ns.red,0),COALESCE(ns.grey,0),COALESCE(ns.unassigned,0),COALESCE(ns.reasons,'[]'::jsonb),COALESCE(ns.computed_at,'epoch'::timestamptz),COALESCE(ns.fresh,0),COALESCE(ns.problems,'{}'::jsonb)
FROM cmdb.services s LEFT JOIN cmdb.node_states ns ON ns.tenant_id=s.tenant_id AND ns.node_kind='system' AND ns.node_id=s.service_uid
WHERE s.tenant_id=$1 AND s.retired_at IS NULL AND ($2='' OR COALESCE(ns.color,'grey')=$2) AND (cardinality($3::text[])=0 OR s.criticality=ANY($3::text[]))
AND ($4='' OR EXISTS(SELECT 1 FROM cmdb.environments e WHERE e.tenant_id=s.tenant_id AND e.service_uid=s.service_uid AND e.kind=$4 AND e.retired_at IS NULL))
AND ($5='' OR ($5='none' AND s.direction_uid IS NULL) OR s.direction_uid::text=$5)
AND (NOT $6 OR COALESCE(ns.color,'grey') IN ('red','yellow')) AND (NOT $7 OR s.business_owner IS NULL)
ORDER BY CASE COALESCE(ns.color,'grey') WHEN 'red' THEN 0 WHEN 'yellow' THEN 1 WHEN 'grey' THEN 2 ELSE 3 END,lower(s.name),s.service_uid OFFSET $8 LIMIT $9`,
		tenant, f.Color, f.Criticality, f.EnvKind, f.Direction, f.Problems, f.NoOwner, f.Offset, f.Limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []SystemState{}
	for rows.Next() {
		var x SystemState
		st := &x.State
		if e = rows.Scan(&x.UID, &x.Name, &x.Criticality, &x.Direction, &x.BusinessOwner, &st.Kind, &st.ID, &st.Color, &st.Hosts, &st.Green, &st.Yellow, &st.Red, &st.Grey, &st.Unassigned, &st.Reasons, &st.ComputedAt, &st.Fresh, &st.Problems); e != nil {
			return nil, e
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// SystemCounters — полоса счётчиков экрана «Системы».
type SystemCounters struct {
	Systems  int `json:"systems"`
	Critical int `json:"critical"`
	Problems int `json:"with_problems"`
	NoOwner  int `json:"without_owner"`
}

func (Store) SystemCounters(ctx context.Context, tx pgx.Tx, tenant string) (SystemCounters, error) {
	var c SystemCounters
	e := tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE s.criticality IN ('high','critical')),count(*) FILTER (WHERE ns.color IN ('red','yellow')),count(*) FILTER (WHERE s.business_owner IS NULL)
FROM cmdb.services s LEFT JOIN cmdb.node_states ns ON ns.tenant_id=s.tenant_id AND ns.node_kind='system' AND ns.node_id=s.service_uid WHERE s.tenant_id=$1 AND s.retired_at IS NULL`, tenant).Scan(&c.Systems, &c.Critical, &c.Problems, &c.NoOwner)
	return c, e
}

// ComponentHostStates — хосты компонента с цветом (сначала проблемные), страница по offset (до 10 000).
func (Store) ComponentHostStates(ctx context.Context, tx pgx.Tx, tenant, component string, offset, limit int) ([]HostState, error) {
	if !identifier.Valid(component) {
		return nil, domain.NotFound
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 || offset > 10000 {
		return nil, domain.Invalid
	}
	rows, e := tx.Query(ctx, `SELECT b.asset_uid::text,COALESCE(h.color,'grey'),COALESCE(h.reasons,'[]'::jsonb),h.last_inventory_at,COALESCE(h.computed_at,'epoch'::timestamptz)
FROM cmdb.bindings b LEFT JOIN cmdb.host_states h ON h.tenant_id=b.tenant_id AND h.asset_uid=b.asset_uid
WHERE b.tenant_id=$1 AND b.component_id=$2 AND b.valid_to IS NULL AND b.status='active'
ORDER BY CASE COALESCE(h.color,'grey') WHEN 'red' THEN 0 WHEN 'yellow' THEN 1 WHEN 'grey' THEN 2 ELSE 3 END,b.asset_uid OFFSET $3 LIMIT $4`, tenant, component, offset, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []HostState{}
	for rows.Next() {
		var h HostState
		if e = rows.Scan(&h.AssetUID, &h.Color, &h.Reasons, &h.LastInventory, &h.ComputedAt); e != nil {
			return nil, e
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
