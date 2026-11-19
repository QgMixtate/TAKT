package app

// C53.02 — состав системы для правой панели экрана «Системы» (макет C53-mockups/6): среды → компоненты → до трёх
// хостов на компонент (сначала проблемные; по запросу — совпавшие по имени или IP) и «ещё N», площадки,
// зависимости «зависит от / от неё зависят» (связи depends_on C26).

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"

	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/cmdb"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

type RSMCompHost struct {
	AssetUID string          `json:"asset_uid"`
	Name     string          `json:"name"`
	IP       string          `json:"ip"`
	Color    string          `json:"color"`
	Reasons  json.RawMessage `json:"reasons"`
}

type RSMCompComponent struct {
	ID       string          `json:"component_id"`
	Name     string          `json:"name"`
	Critical bool            `json:"critical"`
	State    *cmdb.NodeState `json:"state"`
	Hosts    []RSMCompHost   `json:"hosts"`
	More     int             `json:"more"` // ещё хостов под фильтром, не показанных в списке
}

type RSMCompEnvironment struct {
	ID         string             `json:"environment_id"`
	Name       string             `json:"name"`
	Kind       string             `json:"kind"`
	State      *cmdb.NodeState    `json:"state"`
	Components []RSMCompComponent `json:"components"`
}

type RSMRef struct {
	UID  string `json:"service_uid"`
	Name string `json:"name"`
}

type RSMComposition struct {
	System       cmdb.System          `json:"system"`
	State        *cmdb.NodeState      `json:"state"`
	Sites        int                  `json:"sites"`
	Environments []RSMCompEnvironment `json:"environments"`
	DependsOn    []RSMRef             `json:"depends_on"`
	Dependents   []RSMRef             `json:"dependents"`
}

// rsmIPs — адрес хоста для подписи: первый IPv4 из инвентаризации (иначе первый любой).
func rsmIPs(ctx context.Context, tx pgx.Tx, tenant string, uids []string) (map[string]string, error) {
	out := map[string]string{}
	if len(uids) == 0 {
		return out, nil
	}
	rows, e := tx.Query(ctx, `SELECT asset_uid::text,ip FROM (
SELECT asset_uid,jsonb_array_elements(value)->>'ip' AS ip FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=ANY($2::uuid[]) AND section_name='network' AND field_name='addresses' AND jsonb_typeof(value)='array'
UNION ALL SELECT asset_uid,jsonb_array_elements(value::jsonb)->>'ip' FROM inventory.current_facts WHERE tenant_id=$1 AND asset_uid=ANY($2::uuid[]) AND section_name='network' AND fact_key LIKE '%.addresses') x WHERE ip IS NOT NULL ORDER BY 1,2`, tenant, uids)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var uid, ip string
		if e = rows.Scan(&uid, &ip); e != nil {
			return nil, e
		}
		a, err := netip.ParseAddr(ip)
		if err != nil || a.IsLoopback() || a.IsLinkLocalUnicast() {
			continue
		}
		if cur, ok := out[uid]; !ok || (a.Is4() && !strings.Contains(cur, ".")) {
			out[uid] = ip
		}
	}
	return out, rows.Err()
}

func (r *Registry) RSMComposition(ctx context.Context, id accessport.Identity, uid, query, env string, problems bool) (RSMComposition, error) {
	out := RSMComposition{Environments: []RSMCompEnvironment{}, DependsOn: []RSMRef{}, Dependents: []RSMRef{}}
	query = strings.ToLower(strings.TrimSpace(query))
	if !identifier.Valid(uid) || (env != "" && !identifier.Valid(env)) || len(query) > 128 {
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
	envs, comps, e := r.CMDB.SystemEnvironments(ctx, tx, id.TenantID, uid)
	if e != nil {
		return out, e
	}
	envIDs, compIDs := []string{}, []string{}
	for _, x := range envs {
		envIDs = append(envIDs, x.ID)
		for _, c := range comps[x.ID] {
			compIDs = append(compIDs, c.ID)
		}
	}
	sys, e := r.CMDB.NodeStates(ctx, tx, id.TenantID, "system", []string{uid})
	if e != nil {
		return out, e
	}
	out.State = nodePtr(sys, uid)
	envStates, e := r.CMDB.NodeStates(ctx, tx, id.TenantID, "environment", envIDs)
	if e != nil {
		return out, e
	}
	compStates, e := r.CMDB.NodeStates(ctx, tx, id.TenantID, "component", compIDs)
	if e != nil {
		return out, e
	}
	if e = tx.QueryRow(ctx, `SELECT count(DISTINCT a.site_id) FROM cmdb.bindings b JOIN cmdb.components c ON c.tenant_id=b.tenant_id AND c.component_id=b.component_id
JOIN cmdb.environments en ON en.tenant_id=c.tenant_id AND en.environment_id=c.environment_id JOIN assets.assets a ON a.tenant_id=b.tenant_id AND a.asset_uid=b.asset_uid
WHERE b.tenant_id=$1 AND en.service_uid=$2 AND b.valid_to IS NULL AND b.status='active'`, id.TenantID, uid).Scan(&out.Sites); e != nil {
		return out, e
	}
	like := "%" + strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(query) + "%"
	shown := []string{}
	for _, x := range envs {
		if env != "" && x.ID != env {
			continue
		}
		node := RSMCompEnvironment{ID: x.ID, Name: x.Name, Kind: x.Kind, State: nodePtr(envStates, x.ID), Components: []RSMCompComponent{}}
		for _, c := range comps[x.ID] {
			cc := RSMCompComponent{ID: c.ID, Name: c.Name, Critical: c.Critical, State: nodePtr(compStates, c.ID), Hosts: []RSMCompHost{}}
			nameHit := query != "" && strings.Contains(strings.ToLower(c.Name), query)
			q := query
			if nameHit {
				q = "" // совпал компонент — показать его хосты как обычно
			}
			rows, e := tx.Query(ctx, `SELECT b.asset_uid::text,COALESCE(h.color,'grey'),COALESCE(h.reasons,'[]'::jsonb),count(*) OVER () FROM cmdb.bindings b
LEFT JOIN cmdb.host_states h ON h.tenant_id=b.tenant_id AND h.asset_uid=b.asset_uid
WHERE b.tenant_id=$1 AND b.component_id=$2 AND b.valid_to IS NULL AND b.status='active' AND (NOT $3 OR COALESCE(h.color,'grey')<>'green')
AND ($4='' OR EXISTS(SELECT 1 FROM assets.asset_identifiers i WHERE i.tenant_id=b.tenant_id AND i.asset_uid=b.asset_uid AND i.kind='hostname' AND i.valid_to IS NULL AND lower(i.normalized_value) LIKE $5)
 OR EXISTS(SELECT 1 FROM inventory.record_facts12 f WHERE f.tenant_id=b.tenant_id AND f.asset_uid=b.asset_uid AND f.section_name='network' AND f.field_name='addresses' AND jsonb_typeof(f.value)='array' AND f.value::text LIKE $5))
ORDER BY CASE COALESCE(h.color,'grey') WHEN 'red' THEN 0 WHEN 'yellow' THEN 1 WHEN 'grey' THEN 2 ELSE 3 END,b.asset_uid LIMIT 3`, id.TenantID, c.ID, problems, q, like)
			if e != nil {
				return out, e
			}
			total := 0
			for rows.Next() {
				var hst RSMCompHost
				if e = rows.Scan(&hst.AssetUID, &hst.Color, &hst.Reasons, &total); e != nil {
					rows.Close()
					return out, e
				}
				cc.Hosts = append(cc.Hosts, hst)
				shown = append(shown, hst.AssetUID)
			}
			rows.Close()
			if e = rows.Err(); e != nil {
				return out, e
			}
			cc.More = max(total-len(cc.Hosts), 0)
			if query != "" && !nameHit && total == 0 {
				continue // под запросом в компоненте ничего нет
			}
			node.Components = append(node.Components, cc)
		}
		if query != "" && len(node.Components) == 0 {
			continue
		}
		out.Environments = append(out.Environments, node)
	}
	names, e := rsmNames(ctx, tx, id.TenantID, shown)
	if e != nil {
		return out, e
	}
	ips, e := rsmIPs(ctx, tx, id.TenantID, shown)
	if e != nil {
		return out, e
	}
	for i := range out.Environments {
		for j := range out.Environments[i].Components {
			for k := range out.Environments[i].Components[j].Hosts {
				h := &out.Environments[i].Components[j].Hosts[k]
				h.Name, h.IP = names[h.AssetUID], ips[h.AssetUID]
			}
		}
	}
	rels, e := r.CMDB.RelationsOf(ctx, tx, id.TenantID, cmdb.End{Kind: "service", ID: uid})
	if e != nil {
		return out, e
	}
	ref := func(other string) (RSMRef, bool) {
		var name string
		if tx.QueryRow(ctx, "SELECT name FROM cmdb.services WHERE tenant_id=$1 AND service_uid=$2 AND retired_at IS NULL", id.TenantID, other).Scan(&name) != nil {
			return RSMRef{}, false
		}
		return RSMRef{UID: other, Name: name}, true
	}
	for _, rel := range rels {
		if rel.Type != "depends_on" || rel.From.Kind != "service" || rel.To.Kind != "service" {
			continue
		}
		if rel.From.ID == uid {
			if x, ok := ref(rel.To.ID); ok {
				out.DependsOn = append(out.DependsOn, x)
			}
		} else if x, ok := ref(rel.From.ID); ok {
			out.Dependents = append(out.Dependents, x)
		}
	}
	return out, tx.Commit(ctx)
}
