package cmdb

// C54.02 — наполнение РСМ: правила автопривязки хостов к компоненту, предложения с подтверждением оператора, поиск и
// создание пути «система → среда → компонент» для импорта. Сопоставление хоста с правилом (признаки актива) делает
// слой app: модуль хранит только правила и привязки своей схемы.

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

var assetClasses = map[string]bool{"server": true, "workstation": true, "network_device": true, "printer": true, "virtual_machine": true, "unknown": true}

// osFamilies — семейства ОС реестра хостов для образца «класс/семейство» (ISSUES №85, №95).
var osFamilies = map[string]bool{"windows": true, "linux": true, "macos": true, "network": true, "other": true}

type Rule struct {
	ID          string     `json:"rule_id"`
	ComponentID string     `json:"component_id"`
	Kind        string     `json:"kind"`
	Pattern     string     `json:"pattern"`
	Mode        string     `json:"mode"`
	Enabled     bool       `json:"enabled"`
	Revision    string     `json:"revision"`
	CreatedAt   time.Time  `json:"created_at"`
	RetiredAt   *time.Time `json:"retired_at"`
}

// NormalizeRulePattern проверяет и приводит образец правила: подсеть — CIDR; маска имени — символы имени хоста и
// * ?; ПО — подстрока названия; класс — из справочника классов, при необходимости с семейством ОС через «/». OU каталога пока не собирается ни одним источником —
// правило ad_ou отклоняется, чтобы не создавать правило, которое никогда не сработает.
func NormalizeRulePattern(kind, pattern string) (string, bool) {
	p := strings.TrimSpace(pattern)
	if p == "" || len([]rune(p)) > 512 {
		return "", false
	}
	switch kind {
	case "subnet":
		prefix, e := netip.ParsePrefix(p)
		if e != nil {
			return "", false
		}
		return prefix.Masked().String(), true
	case "hostname_glob":
		p = strings.ToLower(p)
		for _, r := range p {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_' || r == '*' || r == '?') {
				return "", false
			}
		}
		return p, true
	case "software":
		return p, true
	case "asset_class": // «класс» или «класс/семейство ОС» (virtual_machine/windows)
		p = strings.ToLower(p)
		class, family, slash := strings.Cut(p, "/")
		return p, assetClasses[class] && (!slash || osFamilies[family])
	}
	return "", false
}

func scanRule(r pgx.Row) (Rule, error) {
	var x Rule
	e := r.Scan(&x.ID, &x.ComponentID, &x.Kind, &x.Pattern, &x.Mode, &x.Enabled, &x.Revision, &x.CreatedAt, &x.RetiredAt)
	return x, e
}

// CreateRule — правило автопривязки к действующему компоненту; mode: propose (по умолчанию) | auto.
func (s Store) CreateRule(ctx context.Context, tx pgx.Tx, tenant, actor, component, kind, pattern, mode string) (Rule, error) {
	if mode == "" {
		mode = "propose"
	}
	p, ok := NormalizeRulePattern(kind, pattern)
	if !identifier.Valid(component) || !ok || (mode != "propose" && mode != "auto") {
		return Rule{}, domain.Invalid
	}
	id := identifier.New()
	tag, e := tx.Exec(ctx, `INSERT INTO cmdb.binding_rules(tenant_id,rule_id,component_id,kind,pattern,mode)
SELECT $1,$2,$3,$4,$5,$6 WHERE EXISTS(SELECT 1 FROM cmdb.components WHERE tenant_id=$1 AND component_id=$3 AND retired_at IS NULL)`, tenant, id, component, kind, p, mode)
	if e != nil {
		return Rule{}, mapWrite(e)
	}
	if tag.RowsAffected() != 1 {
		return Rule{}, domain.NotFound
	}
	if e = s.change(ctx, tx, tenant, "binding_rule", id, "created", actor, map[string]string{"component_id": component, "kind": kind, "pattern": p, "mode": mode}); e != nil {
		return Rule{}, e
	}
	return scanRule(tx.QueryRow(ctx, "SELECT rule_id::text,component_id::text,kind,pattern,mode,enabled,revision::text,created_at,retired_at FROM cmdb.binding_rules WHERE tenant_id=$1 AND rule_id=$2", tenant, id))
}

// RetireRule выводит правило из работы; созданные им привязки и предложения остаются (их снимает оператор).
func (s Store) RetireRule(ctx context.Context, tx pgx.Tx, tenant, actor, rule string) error {
	if !identifier.Valid(rule) {
		return domain.NotFound
	}
	tag, e := tx.Exec(ctx, "UPDATE cmdb.binding_rules SET retired_at=now(),revision=revision+1 WHERE tenant_id=$1 AND rule_id=$2 AND retired_at IS NULL", tenant, rule)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return domain.NotFound
	}
	return s.change(ctx, tx, tenant, "binding_rule", rule, "retired", actor, map[string]string{})
}

// ActiveRules — включённые правила действующих компонентов тенанта (для прохода по хостам).
func (Store) ActiveRules(ctx context.Context, tx pgx.Tx, tenant string) ([]Rule, error) {
	rows, e := tx.Query(ctx, `SELECT r.rule_id::text,r.component_id::text,r.kind,r.pattern,r.mode,r.enabled,r.revision::text,r.created_at,r.retired_at
FROM cmdb.binding_rules r JOIN cmdb.components c ON c.tenant_id=r.tenant_id AND c.component_id=r.component_id
WHERE r.tenant_id=$1 AND r.retired_at IS NULL AND r.enabled AND c.retired_at IS NULL ORDER BY r.created_at,r.rule_id`, tenant)
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

// ApplyRuleMatch записывает совпадение хоста с правилом: auto — сразу действующая привязка, propose — предложение.
// Уже открытая пара или пара, которую оператор раньше отклонил, не трогается (решение оператора не перебивается).
// forcePropose — конфликт правил на этом хосте: даже auto-правило идёт в разбор. Возвращает "", "bound" или "proposed".
func (s Store) ApplyRuleMatch(ctx context.Context, tx pgx.Tx, tenant, actor string, rule Rule, asset string, forcePropose bool) (string, error) {
	var skip bool
	if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cmdb.bindings WHERE tenant_id=$1 AND component_id=$2 AND asset_uid=$3 AND (valid_to IS NULL OR status='rejected'))`, tenant, rule.ComponentID, asset).Scan(&skip); e != nil {
		return "", e
	}
	if skip {
		return "", nil
	}
	if rule.Mode == "auto" && !forcePropose {
		if _, e := s.bind(ctx, tx, tenant, actor, rule.ComponentID, asset, "rule", &rule.ID, false); e != nil {
			return "", e
		}
		return "bound", nil
	}
	id := identifier.New()
	if _, e := tx.Exec(ctx, "INSERT INTO cmdb.bindings(tenant_id,binding_id,component_id,asset_uid,status,is_primary,origin,rule_id,actor_ref) VALUES($1,$2,$3,$4,'proposed',false,'rule',$5,$6)",
		tenant, id, rule.ComponentID, asset, rule.ID, actor); e != nil {
		return "", mapWrite(e)
	}
	detail := map[string]any{"component_id": rule.ComponentID, "asset_uid": asset, "rule_id": rule.ID, "conflict": forcePropose}
	return "proposed", s.change(ctx, tx, tenant, "binding", id, "proposed", actor, detail)
}

// Confirm подтверждает предложение правила: привязка становится действующей (основной — если у хоста основной нет).
func (s Store) Confirm(ctx context.Context, tx pgx.Tx, tenant, actor, binding string) (Binding, error) {
	asset, e := s.lockProposal(ctx, tx, tenant, binding)
	if e != nil {
		return Binding{}, e
	}
	var hasPrimary bool
	if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM (SELECT 1 FROM cmdb.bindings WHERE tenant_id=$1 AND asset_uid=$2 AND valid_to IS NULL AND status='active' AND is_primary FOR UPDATE) x)", tenant, asset).Scan(&hasPrimary); e != nil {
		return Binding{}, e
	}
	if _, e = tx.Exec(ctx, "UPDATE cmdb.bindings SET status='active',is_primary=$3,valid_from=now(),actor_ref=$4 WHERE tenant_id=$1 AND binding_id=$2", tenant, binding, !hasPrimary, actor); e != nil {
		return Binding{}, e
	}
	if e = s.change(ctx, tx, tenant, "binding", binding, "confirmed", actor, map[string]string{"asset_uid": asset}); e != nil {
		return Binding{}, e
	}
	return scanBinding(tx.QueryRow(ctx, "SELECT binding_id::text,component_id::text,asset_uid::text,status,is_primary,origin,rule_id::text,valid_from,valid_to,actor_ref FROM cmdb.bindings WHERE tenant_id=$1 AND binding_id=$2", tenant, binding))
}

// Reject отклоняет предложение: пара больше не предлагается правилами (решение оператора запоминается).
func (s Store) Reject(ctx context.Context, tx pgx.Tx, tenant, actor, binding string) error {
	asset, e := s.lockProposal(ctx, tx, tenant, binding)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "UPDATE cmdb.bindings SET status='rejected',valid_to=now(),actor_ref=$3 WHERE tenant_id=$1 AND binding_id=$2", tenant, binding, actor); e != nil {
		return e
	}
	return s.change(ctx, tx, tenant, "binding", binding, "rejected", actor, map[string]string{"asset_uid": asset})
}

func (Store) lockProposal(ctx context.Context, tx pgx.Tx, tenant, binding string) (string, error) {
	if !identifier.Valid(binding) {
		return "", domain.NotFound
	}
	var asset string
	e := tx.QueryRow(ctx, "SELECT asset_uid::text FROM cmdb.bindings WHERE tenant_id=$1 AND binding_id=$2 AND status='proposed' AND valid_to IS NULL FOR UPDATE", tenant, binding).Scan(&asset)
	if errors.Is(e, pgx.ErrNoRows) {
		return "", domain.NotFound
	}
	return asset, e
}

// Proposals — ожидающие подтверждения предложения правил (очередь разбора), старые сверху.
func (Store) Proposals(ctx context.Context, tx pgx.Tx, tenant string, limit int) ([]Binding, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, e := tx.Query(ctx, "SELECT binding_id::text,component_id::text,asset_uid::text,status,is_primary,origin,rule_id::text,valid_from,valid_to,actor_ref FROM cmdb.bindings WHERE tenant_id=$1 AND status='proposed' AND valid_to IS NULL ORDER BY valid_from,binding_id LIMIT $2", tenant, limit)
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

// ComponentPath находит компонент по именам «система; среда; компонент» (без учёта регистра). Система должна
// существовать; недостающие среду (вид other) и компонент создаёт при create=true, иначе — NotFound.
// created сообщает, что было создано (для предпросмотра импорта).
func (s Store) ComponentPath(ctx context.Context, tx pgx.Tx, tenant, actor, system, environment, component string, create bool) (id string, created []string, err error) {
	if !cleanName(&system, 256) || !cleanName(&environment, 128) || !cleanName(&component, 256) {
		return "", nil, domain.Invalid
	}
	var service string
	e := tx.QueryRow(ctx, "SELECT service_uid::text FROM cmdb.services WHERE tenant_id=$1 AND lower(name)=lower($2) AND retired_at IS NULL ORDER BY created_at LIMIT 1", tenant, system).Scan(&service)
	if errors.Is(e, pgx.ErrNoRows) {
		return "", nil, domain.NotFound
	}
	if e != nil {
		return "", nil, e
	}
	var env string
	e = tx.QueryRow(ctx, "SELECT environment_id::text FROM cmdb.environments WHERE tenant_id=$1 AND service_uid=$2 AND lower(name)=lower($3) AND retired_at IS NULL", tenant, service, environment).Scan(&env)
	if errors.Is(e, pgx.ErrNoRows) {
		if !create {
			return "", []string{"environment", "component"}, nil
		}
		ev, e := s.CreateEnvironment(ctx, tx, tenant, actor, service, environmentKind(environment), environment)
		if e != nil {
			return "", nil, e
		}
		env, created = ev.ID, append(created, "environment")
	} else if e != nil {
		return "", nil, e
	}
	e = tx.QueryRow(ctx, "SELECT component_id::text FROM cmdb.components WHERE tenant_id=$1 AND environment_id=$2 AND lower(name)=lower($3) AND retired_at IS NULL", tenant, env, component).Scan(&id)
	if errors.Is(e, pgx.ErrNoRows) {
		if !create {
			return "", append(created, "component"), nil
		}
		c, e := s.CreateComponent(ctx, tx, tenant, actor, env, component, false, nil)
		if e != nil {
			return "", nil, e
		}
		return c.ID, append(created, "component"), nil
	}
	return id, created, e
}

// environmentKind угадывает вид среды по имени из импорта (прод/тест/…); иначе other.
func environmentKind(name string) string {
	n := strings.ToLower(name)
	for _, k := range []struct{ prefix, kind string }{{"прод", "prod"}, {"prod", "prod"}, {"тест", "test"}, {"test", "test"}, {"разраб", "dev"}, {"dev", "dev"}, {"stag", "stage"}, {"пред", "stage"}, {"dr", "dr"}, {"резерв", "dr"}} {
		if strings.HasPrefix(n, k.prefix) {
			return k.kind
		}
	}
	return "other"
}
