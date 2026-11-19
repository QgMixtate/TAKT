package cmdb

// C54.04 — чтение РСМ для API и Web: направления, дерево системы (среды → компоненты), правила компонента,
// привязки хоста с путём «система / среда / компонент», состояния узлов пачкой.

import (
	"context"
	"errors"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

func (Store) Directions(ctx context.Context, tx pgx.Tx, tenant string) ([]Direction, error) {
	rows, e := tx.Query(ctx, "SELECT direction_uid::text,name,revision::text,created_at,retired_at FROM cmdb.directions WHERE tenant_id=$1 AND retired_at IS NULL ORDER BY lower(name),direction_uid", tenant)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Direction{}
	for rows.Next() {
		var d Direction
		if e = rows.Scan(&d.UID, &d.Name, &d.Revision, &d.CreatedAt, &d.RetiredAt); e != nil {
			return nil, e
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SystemEnvironments — действующие среды системы с компонентами (компоненты — по имени).
func (Store) SystemEnvironments(ctx context.Context, tx pgx.Tx, tenant, system string) ([]Environment, map[string][]Component, error) {
	envs := []Environment{}
	comps := map[string][]Component{}
	rows, e := tx.Query(ctx, "SELECT environment_id::text,service_uid::text,kind,name,revision::text FROM cmdb.environments WHERE tenant_id=$1 AND service_uid=$2 AND retired_at IS NULL ORDER BY CASE kind WHEN 'prod' THEN 0 WHEN 'dr' THEN 1 WHEN 'stage' THEN 2 WHEN 'test' THEN 3 WHEN 'dev' THEN 4 ELSE 5 END,lower(name)", tenant, system)
	if e != nil {
		return nil, nil, e
	}
	for rows.Next() {
		x, e := scanEnvironment(rows)
		if e != nil {
			rows.Close()
			return nil, nil, e
		}
		envs = append(envs, x)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return nil, nil, e
	}
	rows, e = tx.Query(ctx, `SELECT c.component_id::text,c.environment_id::text,c.name,c.critical,c.baseline,c.revision::text FROM cmdb.components c JOIN cmdb.environments e ON e.tenant_id=c.tenant_id AND e.environment_id=c.environment_id
WHERE c.tenant_id=$1 AND e.service_uid=$2 AND c.retired_at IS NULL AND e.retired_at IS NULL ORDER BY lower(c.name)`, tenant, system)
	if e != nil {
		return nil, nil, e
	}
	defer rows.Close()
	for rows.Next() {
		c, e := scanComponent(rows)
		if e != nil {
			return nil, nil, e
		}
		comps[c.EnvironmentID] = append(comps[c.EnvironmentID], c)
	}
	return envs, comps, rows.Err()
}

// ComponentByID — действующий компонент с путём «система / среда».
func (Store) ComponentByID(ctx context.Context, tx pgx.Tx, tenant, id string) (Component, Environment, string, error) {
	if !identifier.Valid(id) {
		return Component{}, Environment{}, "", domain.NotFound
	}
	c, e := scanComponent(tx.QueryRow(ctx, "SELECT c.component_id::text,c.environment_id::text,c.name,c.critical,c.baseline,c.revision::text FROM cmdb.components c WHERE c.tenant_id=$1 AND c.component_id=$2 AND c.retired_at IS NULL", tenant, id))
	if errors.Is(e, pgx.ErrNoRows) {
		return c, Environment{}, "", domain.NotFound
	}
	if e != nil {
		return c, Environment{}, "", e
	}
	env, e := scanEnvironment(tx.QueryRow(ctx, "SELECT environment_id::text,service_uid::text,kind,name,revision::text FROM cmdb.environments WHERE tenant_id=$1 AND environment_id=$2", tenant, c.EnvironmentID))
	if e != nil {
		return c, env, "", e
	}
	var system string
	e = tx.QueryRow(ctx, "SELECT name FROM cmdb.services WHERE tenant_id=$1 AND service_uid=$2", tenant, env.ServiceUID).Scan(&system)
	return c, env, system, e
}

// ComponentRules — действующие правила компонента.
func (Store) ComponentRules(ctx context.Context, tx pgx.Tx, tenant, component string) ([]Rule, error) {
	rows, e := tx.Query(ctx, "SELECT rule_id::text,component_id::text,kind,pattern,mode,enabled,revision::text,created_at,retired_at FROM cmdb.binding_rules WHERE tenant_id=$1 AND component_id=$2 AND retired_at IS NULL ORDER BY created_at,rule_id", tenant, component)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Rule{}
	for rows.Next() {
		x, e := scanRule(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// NodeStates — состояния узлов одного вида пачкой (нет расчёта — узла нет в карте).
func (Store) NodeStates(ctx context.Context, tx pgx.Tx, tenant, kind string, ids []string) (map[string]NodeState, error) {
	out := map[string]NodeState{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, e := tx.Query(ctx, "SELECT node_kind,node_id::text,color,hosts,green,yellow,red,grey,unassigned,reasons,computed_at,fresh,problems FROM cmdb.node_states WHERE tenant_id=$1 AND node_kind=$2 AND node_id=ANY($3::uuid[])", tenant, kind, ids)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		s, e := scanNode(rows)
		if e != nil {
			return nil, e
		}
		out[s.ID] = s
	}
	return out, rows.Err()
}

// HostState — состояние одного хоста (нет расчёта — NotFound).
func (Store) HostState(ctx context.Context, tx pgx.Tx, tenant, asset string) (HostState, error) {
	var h HostState
	e := tx.QueryRow(ctx, "SELECT asset_uid::text,color,reasons,last_inventory_at,computed_at FROM cmdb.host_states WHERE tenant_id=$1 AND asset_uid=$2", tenant, asset).Scan(&h.AssetUID, &h.Color, &h.Reasons, &h.LastInventory, &h.ComputedAt)
	if errors.Is(e, pgx.ErrNoRows) {
		return h, domain.NotFound
	}
	return h, e
}

// BindingPath — привязка с путём для карточки хоста и очереди предложений.
type BindingPath struct {
	Binding     Binding `json:"binding"`
	Component   string  `json:"component_name"`
	Critical    bool    `json:"critical"`
	Environment string  `json:"environment_name"`
	EnvKind     string  `json:"environment_kind"`
	SystemUID   string  `json:"service_uid"`
	System      string  `json:"system_name"`
}

func scanBindingPath(r pgx.Row) (BindingPath, error) {
	var p BindingPath
	b := &p.Binding
	e := r.Scan(&b.ID, &b.ComponentID, &b.AssetUID, &b.Status, &b.Primary, &b.Origin, &b.RuleID, &b.ValidFrom, &b.ValidTo, &b.Actor, &p.Component, &p.Critical, &p.Environment, &p.EnvKind, &p.SystemUID, &p.System)
	return p, e
}

// BindingPaths — привязки по условию: хост (asset) или предложения тенанта (asset пусто; до limit).
func (Store) BindingPaths(ctx context.Context, tx pgx.Tx, tenant, asset string, proposals bool, limit int) ([]BindingPath, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, e := tx.Query(ctx, `SELECT b.binding_id::text,b.component_id::text,b.asset_uid::text,b.status,b.is_primary,b.origin,b.rule_id::text,b.valid_from,b.valid_to,b.actor_ref,
c.name,c.critical,e.name,e.kind,s.service_uid::text,s.name
FROM cmdb.bindings b JOIN cmdb.components c ON c.tenant_id=b.tenant_id AND c.component_id=b.component_id
JOIN cmdb.environments e ON e.tenant_id=c.tenant_id AND e.environment_id=c.environment_id
JOIN cmdb.services s ON s.tenant_id=e.tenant_id AND s.service_uid=e.service_uid
WHERE b.tenant_id=$1 AND b.valid_to IS NULL AND ($2='' OR b.asset_uid=$2::uuid) AND (CASE WHEN $3 THEN b.status='proposed' ELSE b.status<>'rejected' END)
ORDER BY b.is_primary DESC,b.valid_from,b.binding_id LIMIT $4`, tenant, asset, proposals, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []BindingPath{}
	for rows.Next() {
		p, e := scanBindingPath(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ComponentBindings — действующие привязки компонента по хостам (для строки хоста: основная, источник привязки).
func (Store) ComponentBindings(ctx context.Context, tx pgx.Tx, tenant, component string, assets []string) (map[string]Binding, error) {
	out := map[string]Binding{}
	if len(assets) == 0 {
		return out, nil
	}
	rows, e := tx.Query(ctx, "SELECT binding_id::text,component_id::text,asset_uid::text,status,is_primary,origin,rule_id::text,valid_from,valid_to,actor_ref FROM cmdb.bindings WHERE tenant_id=$1 AND component_id=$2 AND asset_uid=ANY($3::uuid[]) AND valid_to IS NULL AND status='active'", tenant, component, assets)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		b, e := scanBinding(rows)
		if e != nil {
			return nil, e
		}
		out[b.AssetUID] = b
	}
	return out, rows.Err()
}

func scanEnvironment(r pgx.Row) (Environment, error) {
	var x Environment
	e := r.Scan(&x.ID, &x.ServiceUID, &x.Kind, &x.Name, &x.Revision)
	return x, e
}

func scanComponent(r pgx.Row) (Component, error) {
	var c Component
	e := r.Scan(&c.ID, &c.EnvironmentID, &c.Name, &c.Critical, &c.Baseline, &c.Revision)
	return c, e
}
