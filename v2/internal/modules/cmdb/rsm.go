package cmdb

// C54.01 — ресурсно-сервисная модель (ADR decisions/C54-rsm.md): направление → система (= сервис C26) → среда →
// компонент → хост. Модуль пишет только в схему cmdb; активы и субъекты ответственности проверяются FK в том же тенанте.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var environmentKinds = map[string]bool{"prod": true, "test": true, "dev": true, "stage": true, "dr": true, "other": true}

func foreignKeyViolation(e error) bool {
	var pg *pgconn.PgError
	return errors.As(e, &pg) && pg.Code == "23503"
}

// mapWrite переводит нарушения ограничений в доменные ошибки: дубль — Conflict, ссылка на чужое/несуществующее — NotFound.
func mapWrite(e error) error {
	switch {
	case e == nil:
		return nil
	case uniqueViolation(e):
		return domain.Conflict
	case foreignKeyViolation(e):
		return domain.NotFound
	}
	return e
}

func cleanName(p *string, limit int) bool {
	if p == nil {
		return false
	}
	n := strings.TrimSpace(*p)
	if n == "" || len([]rune(n)) > limit {
		return false
	}
	*p = n
	return true
}

type Direction struct {
	UID       string     `json:"direction_uid"`
	Name      string     `json:"name"`
	Revision  string     `json:"revision"`
	CreatedAt time.Time  `json:"created_at"`
	RetiredAt *time.Time `json:"retired_at"`
}

func (s Store) CreateDirection(ctx context.Context, tx pgx.Tx, tenant, actor, name string) (Direction, error) {
	if !cleanName(&name, 256) {
		return Direction{}, domain.Invalid
	}
	uid := identifier.New()
	if _, e := tx.Exec(ctx, "INSERT INTO cmdb.directions(tenant_id,direction_uid,name) VALUES($1,$2,$3)", tenant, uid, name); e != nil {
		return Direction{}, mapWrite(e)
	}
	if e := s.change(ctx, tx, tenant, "direction", uid, "created", actor, map[string]string{"name": name}); e != nil {
		return Direction{}, e
	}
	var d Direction
	e := tx.QueryRow(ctx, "SELECT direction_uid::text,name,revision::text,created_at,retired_at FROM cmdb.directions WHERE tenant_id=$1 AND direction_uid=$2", tenant, uid).
		Scan(&d.UID, &d.Name, &d.Revision, &d.CreatedAt, &d.RetiredAt)
	return d, e
}

// SystemFields — поля системы поверх сервиса C26 (nil — не менять; пустая строка в ссылке — снять).
type SystemFields struct {
	DirectionUID      *string `json:"direction_uid,omitempty"`
	BusinessOwner     *string `json:"business_owner,omitempty"`
	ITSubjectID       *string `json:"it_subject_id,omitempty"`
	MaintenanceWindow *string `json:"maintenance_window,omitempty"`
}

type System struct {
	Service
	DirectionUID      *string `json:"direction_uid"`
	BusinessOwner     *string `json:"business_owner"`
	ITSubjectID       *string `json:"it_subject_id"`
	MaintenanceWindow *string `json:"maintenance_window"`
}

func optionalRef(p *string) (set bool, value *string, ok bool) {
	if p == nil {
		return false, nil, true
	}
	if *p == "" {
		return true, nil, true
	}
	return true, p, identifier.Valid(*p)
}

// UpdateSystem меняет поля системы с проверкой ревизии сервиса (общая ревизия: и поля C26, и поля РСМ).
func (s Store) UpdateSystem(ctx context.Context, tx pgx.Tx, tenant, uid, revision, actor string, in SystemFields) (System, error) {
	setDir, dir, okDir := optionalRef(in.DirectionUID)
	setSubj, subj, okSubj := optionalRef(in.ITSubjectID)
	if !okDir || !okSubj || (in.BusinessOwner != nil && len([]rune(*in.BusinessOwner)) > 512) || (in.MaintenanceWindow != nil && len([]rune(*in.MaintenanceWindow)) > 256) {
		return System{}, domain.Invalid
	}
	current, e := s.System(ctx, tx, tenant, uid)
	if e != nil {
		return current, e
	}
	if current.RetiredAt != nil {
		return current, domain.Conflict
	}
	tag, e := tx.Exec(ctx, `UPDATE cmdb.services SET
direction_uid=CASE WHEN $4 THEN $5::uuid ELSE direction_uid END,
it_subject_id=CASE WHEN $6 THEN $7::uuid ELSE it_subject_id END,
business_owner=COALESCE($8,business_owner), maintenance_window=COALESCE($9,maintenance_window), revision=revision+1
WHERE tenant_id=$1 AND service_uid=$2 AND revision::text=$3`, tenant, uid, revision, setDir, dir, setSubj, subj, in.BusinessOwner, in.MaintenanceWindow)
	if e != nil {
		return current, mapWrite(e)
	}
	if tag.RowsAffected() != 1 {
		return current, domain.Revision
	}
	if e = s.change(ctx, tx, tenant, "service", uid, "updated", actor, in); e != nil {
		return current, e
	}
	return s.System(ctx, tx, tenant, uid)
}

func (Store) System(ctx context.Context, tx pgx.Tx, tenant, uid string) (System, error) {
	var out System
	if !identifier.Valid(uid) {
		return out, domain.NotFound
	}
	e := tx.QueryRow(ctx, `SELECT service_uid::text,name,description,criticality,revision::text,created_at,retired_at,
direction_uid::text,business_owner,it_subject_id::text,maintenance_window FROM cmdb.services WHERE tenant_id=$1 AND service_uid=$2`, tenant, uid).
		Scan(&out.UID, &out.Name, &out.Description, &out.Criticality, &out.Revision, &out.CreatedAt, &out.RetiredAt,
			&out.DirectionUID, &out.BusinessOwner, &out.ITSubjectID, &out.MaintenanceWindow)
	if errors.Is(e, pgx.ErrNoRows) {
		e = domain.NotFound
	}
	return out, e
}

type Environment struct {
	ID         string `json:"environment_id"`
	ServiceUID string `json:"service_uid"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Revision   string `json:"revision"`
}

// CreateEnvironment — среда активной системы.
func (s Store) CreateEnvironment(ctx context.Context, tx pgx.Tx, tenant, actor, service, kind, name string) (Environment, error) {
	if !environmentKinds[kind] || !cleanName(&name, 128) || !identifier.Valid(service) {
		return Environment{}, domain.Invalid
	}
	id := identifier.New()
	tag, e := tx.Exec(ctx, `INSERT INTO cmdb.environments(tenant_id,environment_id,service_uid,kind,name)
SELECT $1,$2,$3,$4,$5 WHERE EXISTS(SELECT 1 FROM cmdb.services WHERE tenant_id=$1 AND service_uid=$3 AND retired_at IS NULL)`, tenant, id, service, kind, name)
	if e != nil {
		return Environment{}, mapWrite(e)
	}
	if tag.RowsAffected() != 1 {
		return Environment{}, domain.NotFound
	}
	if e = s.change(ctx, tx, tenant, "environment", id, "created", actor, map[string]string{"service_uid": service, "kind": kind, "name": name}); e != nil {
		return Environment{}, e
	}
	return Environment{ID: id, ServiceUID: service, Kind: kind, Name: name, Revision: "1"}, nil
}

type Component struct {
	ID            string          `json:"component_id"`
	EnvironmentID string          `json:"environment_id"`
	Name          string          `json:"name"`
	Critical      bool            `json:"critical"`
	Baseline      json.RawMessage `json:"baseline"`
	Revision      string          `json:"revision"`
}

func validBaseline(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var m map[string]any
	return len(raw) <= 65536 && json.Unmarshal(raw, &m) == nil && m != nil
}

// CreateComponent — компонент (роль) в действующей среде; эталон — объект JSON до 64 КиБ.
func (s Store) CreateComponent(ctx context.Context, tx pgx.Tx, tenant, actor, environment, name string, critical bool, baseline json.RawMessage) (Component, error) {
	if !cleanName(&name, 256) || !identifier.Valid(environment) || !validBaseline(baseline) {
		return Component{}, domain.Invalid
	}
	if len(baseline) == 0 {
		baseline = json.RawMessage("{}")
	}
	id := identifier.New()
	tag, e := tx.Exec(ctx, `INSERT INTO cmdb.components(tenant_id,component_id,environment_id,name,critical,baseline)
SELECT $1,$2,$3,$4,$5,$6 WHERE EXISTS(SELECT 1 FROM cmdb.environments WHERE tenant_id=$1 AND environment_id=$3 AND retired_at IS NULL)`, tenant, id, environment, name, critical, string(baseline))
	if e != nil {
		return Component{}, mapWrite(e)
	}
	if tag.RowsAffected() != 1 {
		return Component{}, domain.NotFound
	}
	if e = s.change(ctx, tx, tenant, "component", id, "created", actor, map[string]any{"environment_id": environment, "name": name, "critical": critical}); e != nil {
		return Component{}, e
	}
	return Component{ID: id, EnvironmentID: environment, Name: name, Critical: critical, Baseline: baseline, Revision: "1"}, nil
}

type Binding struct {
	ID          string     `json:"binding_id"`
	ComponentID string     `json:"component_id"`
	AssetUID    string     `json:"asset_uid"`
	Status      string     `json:"status"`
	Primary     bool       `json:"is_primary"`
	Origin      string     `json:"origin"`
	RuleID      *string    `json:"rule_id"`
	ValidFrom   time.Time  `json:"valid_from"`
	ValidTo     *time.Time `json:"valid_to"`
	Actor       string     `json:"actor_ref"`
}

func scanBinding(r pgx.Row) (Binding, error) {
	var b Binding
	e := r.Scan(&b.ID, &b.ComponentID, &b.AssetUID, &b.Status, &b.Primary, &b.Origin, &b.RuleID, &b.ValidFrom, &b.ValidTo, &b.Actor)
	return b, e
}

// Bind привязывает хост к компоненту. Первая действующая привязка хоста становится основной; primary=true переносит
// «основную» на эту привязку. Повторная привязка той же пары — Conflict. Хост может входить в несколько компонентов.
func (s Store) Bind(ctx context.Context, tx pgx.Tx, tenant, actor, component, asset, origin string, primary bool) (Binding, error) {
	if !identifier.Valid(component) || !identifier.Valid(asset) || (origin != "manual" && origin != "import") {
		return Binding{}, domain.Invalid
	}
	var alive bool
	if e := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM cmdb.components WHERE tenant_id=$1 AND component_id=$2 AND retired_at IS NULL)", tenant, component).Scan(&alive); e != nil {
		return Binding{}, e
	}
	if !alive {
		return Binding{}, domain.NotFound
	}
	// блокировка открытых привязок хоста: основная назначается без гонки
	var open int
	if e := tx.QueryRow(ctx, "SELECT count(*) FROM (SELECT 1 FROM cmdb.bindings WHERE tenant_id=$1 AND asset_uid=$2 AND valid_to IS NULL AND status='active' FOR UPDATE) x", tenant, asset).Scan(&open); e != nil {
		return Binding{}, e
	}
	if primary && open > 0 {
		if _, e := tx.Exec(ctx, "UPDATE cmdb.bindings SET is_primary=false WHERE tenant_id=$1 AND asset_uid=$2 AND valid_to IS NULL AND is_primary", tenant, asset); e != nil {
			return Binding{}, e
		}
	}
	id := identifier.New()
	if _, e := tx.Exec(ctx, "INSERT INTO cmdb.bindings(tenant_id,binding_id,component_id,asset_uid,status,is_primary,origin,actor_ref) VALUES($1,$2,$3,$4,'active',$5,$6,$7)",
		tenant, id, component, asset, primary || open == 0, origin, actor); e != nil {
		return Binding{}, mapWrite(e)
	}
	if e := s.change(ctx, tx, tenant, "binding", id, "created", actor, map[string]any{"component_id": component, "asset_uid": asset, "origin": origin, "primary": primary || open == 0}); e != nil {
		return Binding{}, e
	}
	return scanBinding(tx.QueryRow(ctx, "SELECT binding_id::text,component_id::text,asset_uid::text,status,is_primary,origin,rule_id::text,valid_from,valid_to,actor_ref FROM cmdb.bindings WHERE tenant_id=$1 AND binding_id=$2", tenant, id))
}

// SetPrimary делает действующую привязку основной для её хоста; прежняя основная снимается.
func (s Store) SetPrimary(ctx context.Context, tx pgx.Tx, tenant, actor, binding string) (Binding, error) {
	if !identifier.Valid(binding) {
		return Binding{}, domain.NotFound
	}
	var asset string
	var primary bool
	e := tx.QueryRow(ctx, "SELECT asset_uid::text,is_primary FROM cmdb.bindings WHERE tenant_id=$1 AND binding_id=$2 AND valid_to IS NULL AND status='active' FOR UPDATE", tenant, binding).Scan(&asset, &primary)
	if errors.Is(e, pgx.ErrNoRows) {
		return Binding{}, domain.NotFound
	}
	if e != nil {
		return Binding{}, e
	}
	if !primary {
		if _, e = tx.Exec(ctx, "UPDATE cmdb.bindings SET is_primary=false WHERE tenant_id=$1 AND asset_uid=$2 AND valid_to IS NULL AND is_primary", tenant, asset); e != nil {
			return Binding{}, e
		}
		if _, e = tx.Exec(ctx, "UPDATE cmdb.bindings SET is_primary=true WHERE tenant_id=$1 AND binding_id=$2", tenant, binding); e != nil {
			return Binding{}, e
		}
		if e = s.change(ctx, tx, tenant, "binding", binding, "updated", actor, map[string]any{"asset_uid": asset, "primary": true}); e != nil {
			return Binding{}, e
		}
	}
	return scanBinding(tx.QueryRow(ctx, "SELECT binding_id::text,component_id::text,asset_uid::text,status,is_primary,origin,rule_id::text,valid_from,valid_to,actor_ref FROM cmdb.bindings WHERE tenant_id=$1 AND binding_id=$2", tenant, binding))
}

// Unbind закрывает привязку; если она была основной, основной становится самая ранняя из оставшихся действующих.
func (s Store) Unbind(ctx context.Context, tx pgx.Tx, tenant, actor, binding string) error {
	if !identifier.Valid(binding) {
		return domain.NotFound
	}
	var asset string
	var primary bool
	e := tx.QueryRow(ctx, "SELECT asset_uid::text,is_primary FROM cmdb.bindings WHERE tenant_id=$1 AND binding_id=$2 AND valid_to IS NULL FOR UPDATE", tenant, binding).Scan(&asset, &primary)
	if errors.Is(e, pgx.ErrNoRows) {
		return domain.NotFound
	}
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "UPDATE cmdb.bindings SET valid_to=now(),is_primary=false WHERE tenant_id=$1 AND binding_id=$2", tenant, binding); e != nil {
		return e
	}
	if primary {
		if _, e = tx.Exec(ctx, `UPDATE cmdb.bindings SET is_primary=true WHERE tenant_id=$1 AND binding_id=(SELECT binding_id FROM cmdb.bindings
WHERE tenant_id=$1 AND asset_uid=$2 AND valid_to IS NULL AND status='active' ORDER BY valid_from,binding_id LIMIT 1)`, tenant, asset); e != nil {
			return e
		}
	}
	return s.change(ctx, tx, tenant, "binding", binding, "closed", actor, map[string]string{"asset_uid": asset})
}

// AssetBindings — действующие и предложенные привязки хоста (карточка хоста: «входит в»).
func (Store) AssetBindings(ctx context.Context, tx pgx.Tx, tenant, asset string) ([]Binding, error) {
	rows, e := tx.Query(ctx, "SELECT binding_id::text,component_id::text,asset_uid::text,status,is_primary,origin,rule_id::text,valid_from,valid_to,actor_ref FROM cmdb.bindings WHERE tenant_id=$1 AND asset_uid=$2 AND valid_to IS NULL AND status<>'rejected' ORDER BY is_primary DESC,valid_from,binding_id", tenant, asset)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Binding{}
	for rows.Next() {
		b, e := scanBinding(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// AddComponentDependency — компонент → компонент (обе стороны действующие, в одном тенанте).
func (s Store) AddComponentDependency(ctx context.Context, tx pgx.Tx, tenant, actor, from, to string) (string, error) {
	if !identifier.Valid(from) || !identifier.Valid(to) || from == to {
		return "", domain.Invalid
	}
	id := identifier.New()
	tag, e := tx.Exec(ctx, `INSERT INTO cmdb.component_dependencies(tenant_id,dependency_id,from_component_id,to_component_id,actor_ref)
SELECT $1,$2,$3,$4,$5 WHERE (SELECT count(*) FROM cmdb.components WHERE tenant_id=$1 AND component_id IN ($3,$4) AND retired_at IS NULL)=2`, tenant, id, from, to, actor)
	if e != nil {
		return "", mapWrite(e)
	}
	if tag.RowsAffected() != 1 {
		return "", domain.NotFound
	}
	return id, s.change(ctx, tx, tenant, "component_dependency", id, "created", actor, map[string]string{"from_component_id": from, "to_component_id": to})
}

// RetargetBindings переносит открытые привязки поглощённого актива на канонический (C25.03): пара, уже открытая у
// канонического, закрывается как дубль; основной у канонического остаётся его прежняя основная (если была).
func (s Store) RetargetBindings(ctx context.Context, tx pgx.Tx, tenant, from, to, actor string) (int, error) {
	rows, e := tx.Query(ctx, "SELECT binding_id::text,component_id::text,asset_uid::text,status,is_primary,origin,rule_id::text,valid_from,valid_to,actor_ref FROM cmdb.bindings WHERE tenant_id=$1 AND asset_uid=$2 AND valid_to IS NULL FOR UPDATE", tenant, from)
	if e != nil {
		return 0, e
	}
	var list []Binding
	for rows.Next() {
		b, e := scanBinding(rows)
		if e != nil {
			rows.Close()
			return 0, e
		}
		list = append(list, b)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return 0, e
	}
	var targetHasPrimary bool
	if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM cmdb.bindings WHERE tenant_id=$1 AND asset_uid=$2 AND valid_to IS NULL AND is_primary)", tenant, to).Scan(&targetHasPrimary); e != nil {
		return 0, e
	}
	moved := 0
	for _, b := range list {
		if _, e = tx.Exec(ctx, "UPDATE cmdb.bindings SET valid_to=now(),is_primary=false WHERE tenant_id=$1 AND binding_id=$2", tenant, b.ID); e != nil {
			return moved, e
		}
		primary := b.Primary && !targetHasPrimary
		id := identifier.New()
		tag, e := tx.Exec(ctx, `INSERT INTO cmdb.bindings(tenant_id,binding_id,component_id,asset_uid,status,is_primary,origin,rule_id,actor_ref)
SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9 WHERE NOT EXISTS(SELECT 1 FROM cmdb.bindings WHERE tenant_id=$1 AND component_id=$3 AND asset_uid=$4 AND valid_to IS NULL AND status<>'rejected')`,
			tenant, id, b.ComponentID, to, b.Status, primary, b.Origin, b.RuleID, actor)
		if e != nil {
			return moved, e
		}
		detail := map[string]string{"from_asset_uid": from, "to_asset_uid": to}
		if tag.RowsAffected() == 1 {
			detail["new_binding_id"], moved = id, moved+1
			if primary {
				targetHasPrimary = true
			}
		} else {
			detail["result"] = "retired_duplicate"
		}
		if e = s.change(ctx, tx, tenant, "binding", b.ID, "retargeted", actor, detail); e != nil {
			return moved, e
		}
	}
	return moved, nil
}
