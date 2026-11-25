package app

// C54.04 — API РСМ (контракт contracts/c54-rsm.schema.json): обзор и дерево состояния, системы, среды, компоненты,
// привязки, правила и предложения, импорт CSV, «хосты вне систем», РСМ в карточке актива. Маршруты собраны в
// отдельную таблицу rsmHandlers — модуль включается/выключается целиком (лицензирование модулей, C56).

import (
	"context"
	"encoding/json"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/cmdb"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

type RSMDirection struct {
	cmdb.Direction
	State *cmdb.NodeState `json:"state"`
}

type RSMOverview struct {
	Tenant     string              `json:"tenant_id"`
	State      *cmdb.NodeState     `json:"state"`
	Directions []RSMDirection      `json:"directions"`
	Proposals  int                 `json:"proposals"`
	Counters   cmdb.SystemCounters `json:"counters"`
	Unassigned int                 `json:"unassigned"` // считается сразу, не ждёт пересчёта
}

type RSMSystemPage struct {
	Items      []cmdb.SystemState `json:"items"`
	Offset     int                `json:"offset"`
	NextOffset *int               `json:"next_offset"`
}

type RSMComponentNode struct {
	cmdb.Component
	State *cmdb.NodeState `json:"state"`
}

type RSMEnvironment struct {
	cmdb.Environment
	State      *cmdb.NodeState    `json:"state"`
	Components []RSMComponentNode `json:"components"`
}

type RSMSystemDetail struct {
	System       cmdb.System      `json:"system"`
	State        *cmdb.NodeState  `json:"state"`
	Environments []RSMEnvironment `json:"environments"`
}

type RSMHostRow struct {
	AssetUID      string          `json:"asset_uid"`
	Name          string          `json:"name"`
	Color         string          `json:"color"`
	Reasons       json.RawMessage `json:"reasons"`
	LastInventory *time.Time      `json:"last_inventory_at"`
	BindingID     string          `json:"binding_id"`
	Primary       bool            `json:"is_primary"`
	Origin        string          `json:"origin"`
}

type RSMComponentDetail struct {
	Component   cmdb.Component   `json:"component"`
	Environment cmdb.Environment `json:"environment"`
	System      string           `json:"system_name"`
	State       *cmdb.NodeState  `json:"state"`
	Rules       []cmdb.Rule      `json:"rules"`
	Hosts       []RSMHostRow     `json:"hosts"`
	Offset      int              `json:"offset"`
	NextOffset  *int             `json:"next_offset"`
}

type RSMProposal struct {
	cmdb.BindingPath
	AssetName string `json:"asset_name"`
}

type RSMProposalList struct {
	Items []RSMProposal `json:"items"`
}

type RSMAssetRef struct {
	AssetUID string `json:"asset_uid"`
	Name     string `json:"name"`
	// C53.07: для очереди «Хосты вне систем» — IP, ОС, площадка, когда хост появился в реестре.
	IP        string     `json:"ip,omitempty"`
	OS        *string    `json:"os,omitempty"`
	Site      string     `json:"site,omitempty"`
	Since     *time.Time `json:"since,omitempty"`
	Inventory *time.Time `json:"last_inventory_at,omitempty"`
}

type RSMUnassignedPage struct {
	Total      int           `json:"total"`
	Items      []RSMAssetRef `json:"items"`
	NextCursor *string       `json:"next_cursor"`
}

type AssetRSM struct {
	AssetUID string             `json:"asset_uid"`
	State    *cmdb.HostState    `json:"state"`
	Bindings []cmdb.BindingPath `json:"bindings"`
}

func nodePtr(m map[string]cmdb.NodeState, id string) *cmdb.NodeState {
	if s, ok := m[id]; ok {
		return &s
	}
	return nil
}

// rsmNames — подпись хоста: имя из карточки, иначе текущее имя ПК, иначе пусто (Web покажет UID).
func rsmNames(ctx context.Context, tx pgx.Tx, tenant string, uids []string) (map[string]string, error) {
	out := map[string]string{}
	if len(uids) == 0 {
		return out, nil
	}
	rows, e := tx.Query(ctx, `SELECT a.asset_uid::text,COALESCE(NULLIF(b.display_name,''),(SELECT i.normalized_value FROM assets.asset_identifiers i
WHERE i.tenant_id=a.tenant_id AND i.asset_uid=a.asset_uid AND i.kind='hostname' AND i.valid_to IS NULL ORDER BY i.valid_from DESC LIMIT 1),'')
FROM assets.assets a LEFT JOIN assets.asset_business_fields b ON b.tenant_id=a.tenant_id AND b.asset_uid=a.asset_uid
WHERE a.tenant_id=$1 AND a.asset_uid=ANY($2::uuid[])`, tenant, uids)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var uid, name string
		if e = rows.Scan(&uid, &name); e != nil {
			return nil, e
		}
		out[uid] = name
	}
	return out, rows.Err()
}

func (r *Registry) RSMOverview(ctx context.Context, id accessport.Identity) (RSMOverview, error) {
	out := RSMOverview{Tenant: id.TenantID, Directions: []RSMDirection{}}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if s, e := r.CMDB.Node(ctx, tx, id.TenantID, "tenant", id.TenantID); e == nil {
		out.State = &s
	} else if e != domain.NotFound {
		return out, e
	}
	dirs, e := r.CMDB.Directions(ctx, tx, id.TenantID)
	if e != nil {
		return out, e
	}
	ids := make([]string, len(dirs))
	for i, d := range dirs {
		ids[i] = d.UID
	}
	states, e := r.CMDB.NodeStates(ctx, tx, id.TenantID, "direction", ids)
	if e != nil {
		return out, e
	}
	for _, d := range dirs {
		out.Directions = append(out.Directions, RSMDirection{Direction: d, State: nodePtr(states, d.UID)})
	}
	if e = tx.QueryRow(ctx, "SELECT count(*) FROM cmdb.bindings WHERE tenant_id=$1 AND status='proposed' AND valid_to IS NULL", id.TenantID).Scan(&out.Proposals); e != nil {
		return out, e
	}
	if out.Counters, e = r.CMDB.SystemCounters(ctx, tx, id.TenantID); e != nil {
		return out, e
	}
	if out.Unassigned, e = r.CMDB.UnassignedCount(ctx, tx, id.TenantID); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

func (r *Registry) RSMSystems(ctx context.Context, id accessport.Identity, f cmdb.SystemFilter) (RSMSystemPage, error) {
	offset, limit := f.Offset, f.Limit
	out := RSMSystemPage{Offset: offset, Items: []cmdb.SystemState{}}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	f.Limit = limit + 1
	items, e := r.CMDB.SystemsByState(ctx, tx, id.TenantID, f)
	if e != nil {
		return out, e
	}
	if len(items) > limit {
		items, out.NextOffset = items[:limit], new(int)
		*out.NextOffset = offset + limit
	}
	out.Items = items
	return out, tx.Commit(ctx)
}

func (r *Registry) RSMSystem(ctx context.Context, id accessport.Identity, uid string) (RSMSystemDetail, error) {
	out := RSMSystemDetail{Environments: []RSMEnvironment{}}
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
	envStates, e := r.CMDB.NodeStates(ctx, tx, id.TenantID, "environment", envIDs)
	if e != nil {
		return out, e
	}
	compStates, e := r.CMDB.NodeStates(ctx, tx, id.TenantID, "component", compIDs)
	if e != nil {
		return out, e
	}
	out.State = nodePtr(sys, uid)
	for _, x := range envs {
		node := RSMEnvironment{Environment: x, State: nodePtr(envStates, x.ID), Components: []RSMComponentNode{}}
		for _, c := range comps[x.ID] {
			node.Components = append(node.Components, RSMComponentNode{Component: c, State: nodePtr(compStates, c.ID)})
		}
		out.Environments = append(out.Environments, node)
	}
	return out, tx.Commit(ctx)
}

func (r *Registry) RSMComponent(ctx context.Context, id accessport.Identity, component string, offset, limit int) (RSMComponentDetail, error) {
	out := RSMComponentDetail{Offset: offset, Rules: []cmdb.Rule{}, Hosts: []RSMHostRow{}}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if out.Component, out.Environment, out.System, e = r.CMDB.ComponentByID(ctx, tx, id.TenantID, component); e != nil {
		return out, e
	}
	states, e := r.CMDB.NodeStates(ctx, tx, id.TenantID, "component", []string{component})
	if e != nil {
		return out, e
	}
	out.State = nodePtr(states, component)
	if out.Rules, e = r.CMDB.ComponentRules(ctx, tx, id.TenantID, component); e != nil {
		return out, e
	}
	hosts, e := r.CMDB.ComponentHostStates(ctx, tx, id.TenantID, component, offset, limit+1)
	if e != nil {
		return out, e
	}
	if len(hosts) > limit {
		hosts, out.NextOffset = hosts[:limit], new(int)
		*out.NextOffset = offset + limit
	}
	uids := make([]string, len(hosts))
	for i, h := range hosts {
		uids[i] = h.AssetUID
	}
	names, e := rsmNames(ctx, tx, id.TenantID, uids)
	if e != nil {
		return out, e
	}
	bindings, e := r.CMDB.ComponentBindings(ctx, tx, id.TenantID, component, uids)
	if e != nil {
		return out, e
	}
	for _, h := range hosts {
		b := bindings[h.AssetUID]
		out.Hosts = append(out.Hosts, RSMHostRow{AssetUID: h.AssetUID, Name: names[h.AssetUID], Color: h.Color, Reasons: h.Reasons, LastInventory: h.LastInventory, BindingID: b.ID, Primary: b.Primary, Origin: b.Origin})
	}
	return out, tx.Commit(ctx)
}

func (r *Registry) RSMProposals(ctx context.Context, id accessport.Identity) (RSMProposalList, error) {
	out := RSMProposalList{Items: []RSMProposal{}}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	list, e := r.CMDB.BindingPaths(ctx, tx, id.TenantID, "", true, 500)
	if e != nil {
		return out, e
	}
	uids := make([]string, len(list))
	for i, p := range list {
		uids[i] = p.Binding.AssetUID
	}
	names, e := rsmNames(ctx, tx, id.TenantID, uids)
	if e != nil {
		return out, e
	}
	for _, p := range list {
		out.Items = append(out.Items, RSMProposal{BindingPath: p, AssetName: names[p.Binding.AssetUID]})
	}
	return out, tx.Commit(ctx)
}

func (r *Registry) RSMUnassigned(ctx context.Context, id accessport.Identity, after string, limit int) (RSMUnassignedPage, error) {
	out := RSMUnassignedPage{Items: []RSMAssetRef{}}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if out.Total, e = r.CMDB.UnassignedCount(ctx, tx, id.TenantID); e != nil {
		return out, e
	}
	uids, e := r.CMDB.UnassignedHosts(ctx, tx, id.TenantID, after, limit+1)
	if e != nil {
		return out, e
	}
	if len(uids) > limit {
		uids = uids[:limit]
		next := uids[limit-1]
		out.NextCursor = &next
	}
	names, e := rsmNames(ctx, tx, id.TenantID, uids)
	if e != nil {
		return out, e
	}
	ips, e := rsmIPs(ctx, tx, id.TenantID, uids)
	if e != nil {
		return out, e
	}
	sites, since := map[string]string{}, map[string]time.Time{}
	rows, e := tx.Query(ctx, `SELECT a.asset_uid::text,COALESCE(st.name,''),a.created_at FROM assets.assets a LEFT JOIN scope.sites st ON st.tenant_id=a.tenant_id AND st.site_id=a.site_id
WHERE a.tenant_id=$1 AND a.asset_uid=ANY($2::uuid[])`, id.TenantID, uids)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var u, site string
		var t time.Time
		if e = rows.Scan(&u, &site, &t); e != nil {
			rows.Close()
			return out, e
		}
		sites[u], since[u] = site, t
	}
	rows.Close()
	list := make([]*contracts.Asset, 0, len(uids))
	for _, u := range uids {
		if a, e := r.Assets.Get(ctx, tx, id.TenantID, u); e == nil {
			a := a
			list = append(list, &a)
		}
	}
	if e = r.Inventory.EnrichMany(ctx, tx, list); e != nil {
		return out, e
	}
	byUID := map[string]*contracts.Asset{}
	for _, a := range list {
		byUID[a.UID] = a
	}
	for _, u := range uids {
		ref := RSMAssetRef{AssetUID: u, Name: names[u], IP: ips[u], Site: sites[u]}
		if t, ok := since[u]; ok {
			ref.Since = &t
		}
		if a := byUID[u]; a != nil {
			ref.OS, ref.Inventory = a.OS, a.LastInventory
		}
		out.Items = append(out.Items, ref)
	}
	return out, tx.Commit(ctx)
}

func (r *Registry) AssetRSM(ctx context.Context, id accessport.Identity, uid string) (AssetRSM, error) {
	out := AssetRSM{AssetUID: uid, Bindings: []cmdb.BindingPath{}}
	if !identifier.Valid(uid) {
		return out, domain.NotFound
	}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if _, e = r.Assets.Get(ctx, tx, id.TenantID, uid); e != nil {
		return out, e
	}
	if s, e := r.CMDB.HostState(ctx, tx, id.TenantID, uid); e == nil {
		out.State = &s
	} else if e != domain.NotFound {
		return out, e
	}
	if out.Bindings, e = r.CMDB.BindingPaths(ctx, tx, id.TenantID, uid, false, 200); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

// rsmWrite — изменение РСМ в транзакции записи реестра с аудитом.
func (r *Registry) rsmWrite(ctx context.Context, id accessport.Identity, action, object string, fn func(tx pgx.Tx) (string, error)) error {
	tx, e := r.assetOperationTx(ctx, id)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	ref, e := fn(tx)
	if e != nil {
		return e
	}
	if ref == "" {
		ref = identifier.New()
	}
	if e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "cmdb.rsm_"+action, object, ref); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

type rsmRoute struct {
	permission string
	handler    http.Handler
}

func offsetLimit(w http.ResponseWriter, q map[string][]string) (int, int, bool) {
	get := func(k string) string {
		if v := q[k]; len(v) == 1 {
			return v[0]
		}
		return ""
	}
	offset, limit := 0, 100
	var err error
	if v := get("offset"); v != "" {
		if offset, err = strconv.Atoi(v); err != nil || offset < 0 || offset > 10000 {
			access.APIError(w, 400, "INVALID_QUERY")
			return 0, 0, false
		}
	}
	if v := get("limit"); v != "" {
		if limit, err = strconv.Atoi(v); err != nil || limit < 1 || limit > 500 {
			access.APIError(w, 400, "INVALID_QUERY")
			return 0, 0, false
		}
	}
	return offset, limit, true
}

func (r *Registry) rsmHandlers() map[string]rsmRoute {
	read := func(fn func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity)) rsmRoute {
		return rsmRoute{"assets:read", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx, cancel, id := cmdbContext(req)
			defer cancel()
			fn(w, req, ctx, id)
		})}
	}
	write := func(into func() any, fn func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity, body any)) rsmRoute {
		return rsmRoute{"assets:write", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			body := into()
			if !readOperationBody(w, req, body) {
				return
			}
			ctx, cancel, id := cmdbContext(req)
			defer cancel()
			fn(w, req, ctx, id, body)
		})}
	}
	reply := func(w http.ResponseWriter, req *http.Request, out any, e error) {
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, out)
	}
	created := func(w http.ResponseWriter, req *http.Request, out any, e error) {
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSONStatus(w, http.StatusCreated, out)
	}
	none := func() any { return &struct{}{} }
	h := map[string]rsmRoute{}
	h["GET /api/v1/rsm/overview"] = read(func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		out, e := r.RSMOverview(ctx, id)
		reply(w, req, out, e)
	})
	h["GET /api/v1/rsm/systems"] = read(func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity) {
		q, ok := queryOnly(w, req, "color", "criticality", "env", "direction", "problems", "no_owner", "q", "offset", "limit")
		if !ok {
			return
		}
		offset, limit, ok := offsetLimit(w, q)
		if !ok {
			return
		}
		f := cmdb.SystemFilter{Color: q.Get("color"), EnvKind: q.Get("env"), Direction: q.Get("direction"), Problems: q.Get("problems") == "true", NoOwner: q.Get("no_owner") == "true", Query: strings.TrimSpace(q.Get("q")), Offset: offset, Limit: limit}
		if v := q.Get("criticality"); v != "" {
			f.Criticality = strings.Split(v, ",")
		}
		out, e := r.RSMSystems(ctx, id, f)
		reply(w, req, out, e)
	})
	h["GET /api/v1/rsm/systems/{service_uid}"] = read(func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		out, e := r.RSMSystem(ctx, id, req.PathValue("service_uid"))
		reply(w, req, out, e)
	})
	type systemPatch struct {
		Revision string `json:"revision"`
		cmdb.SystemFields
	}
	h["GET /api/v1/rsm/systems/{service_uid}/composition"] = read(func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity) {
		q, ok := queryOnly(w, req, "q", "env", "problems")
		if !ok {
			return
		}
		out, e := r.RSMComposition(ctx, id, req.PathValue("service_uid"), q.Get("q"), q.Get("env"), q.Get("problems") == "true")
		reply(w, req, out, e)
	})
	h["GET /api/v1/rsm/systems/{service_uid}/card"] = read(func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		out, e := r.RSMSystemCard(ctx, id, req.PathValue("service_uid"))
		reply(w, req, out, e)
	})
	h["GET /api/v1/rsm/components/{component_id}/card"] = read(func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity) {
		q, ok := queryOnly(w, req, "q", "site", "color", "offset", "limit")
		if !ok {
			return
		}
		offset, limit, ok := offsetLimit(w, q)
		if !ok {
			return
		}
		out, e := r.RSMComponentCard(ctx, id, req.PathValue("component_id"), q.Get("q"), q.Get("site"), q.Get("color"), offset, limit)
		reply(w, req, out, e)
	})
	h["PATCH /api/v1/rsm/systems/{service_uid}"] = write(func() any { return &systemPatch{} }, func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity, body any) {
		p := body.(*systemPatch)
		var out cmdb.System
		uid := req.PathValue("service_uid")
		e := r.rsmWrite(ctx, id, "system_updated", "service", func(tx pgx.Tx) (string, error) {
			var e error
			out, e = r.CMDB.UpdateSystem(ctx, tx, id.TenantID, uid, p.Revision, id.UserID, p.SystemFields)
			return uid, e
		})
		reply(w, req, out, e)
	})
	h["GET /api/v1/rsm/directions"] = read(func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		out, e := r.RSMOverview(ctx, id)
		reply(w, req, map[string]any{"items": out.Directions}, e)
	})
	type named struct {
		Name string `json:"name"`
	}
	h["POST /api/v1/rsm/directions"] = write(func() any { return &named{} }, func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity, body any) {
		var out cmdb.Direction
		e := r.rsmWrite(ctx, id, "direction_created", "direction", func(tx pgx.Tx) (string, error) {
			var e error
			out, e = r.CMDB.CreateDirection(ctx, tx, id.TenantID, id.UserID, body.(*named).Name)
			return out.UID, e
		})
		created(w, req, out, e)
	})
	type envInput struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	}
	h["POST /api/v1/rsm/systems/{service_uid}/environments"] = write(func() any { return &envInput{} }, func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity, body any) {
		in := body.(*envInput)
		var out cmdb.Environment
		e := r.rsmWrite(ctx, id, "environment_created", "environment", func(tx pgx.Tx) (string, error) {
			var e error
			out, e = r.CMDB.CreateEnvironment(ctx, tx, id.TenantID, id.UserID, req.PathValue("service_uid"), in.Kind, in.Name)
			return out.ID, e
		})
		created(w, req, out, e)
	})
	type compInput struct {
		Name     string          `json:"name"`
		Critical bool            `json:"critical"`
		Baseline json.RawMessage `json:"baseline,omitempty"`
	}
	h["POST /api/v1/rsm/environments/{environment_id}/components"] = write(func() any { return &compInput{} }, func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity, body any) {
		in := body.(*compInput)
		var out cmdb.Component
		e := r.rsmWrite(ctx, id, "component_created", "component", func(tx pgx.Tx) (string, error) {
			var e error
			out, e = r.CMDB.CreateComponent(ctx, tx, id.TenantID, id.UserID, req.PathValue("environment_id"), in.Name, in.Critical, in.Baseline)
			return out.ID, e
		})
		created(w, req, out, e)
	})
	h["GET /api/v1/rsm/components/{component_id}"] = read(func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity) {
		q, ok := queryOnly(w, req, "offset", "limit")
		if !ok {
			return
		}
		offset, limit, ok := offsetLimit(w, q)
		if !ok {
			return
		}
		out, e := r.RSMComponent(ctx, id, req.PathValue("component_id"), offset, limit)
		reply(w, req, out, e)
	})
	type bulkInput struct {
		Assets []string `json:"asset_uids"`
	}
	h["POST /api/v1/rsm/components/{component_id}/bindings"] = write(func() any { return &bulkInput{} }, func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity, body any) {
		out, e := r.BulkBind(ctx, id, req.PathValue("component_id"), body.(*bulkInput).Assets)
		reply(w, req, out, e)
	})
	h["POST /api/v1/rsm/bindings/{binding_id}/unbind"] = write(none, func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity, _ any) {
		uid := req.PathValue("binding_id")
		e := r.rsmWrite(ctx, id, "unbound", "binding", func(tx pgx.Tx) (string, error) {
			return uid, r.CMDB.Unbind(ctx, tx, id.TenantID, id.UserID, uid)
		})
		reply(w, req, map[string]string{"binding_id": uid}, e)
	})
	h["POST /api/v1/rsm/bindings/{binding_id}/primary"] = write(none, func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity, _ any) {
		var out cmdb.Binding
		uid := req.PathValue("binding_id")
		e := r.rsmWrite(ctx, id, "primary_set", "binding", func(tx pgx.Tx) (string, error) {
			var e error
			out, e = r.CMDB.SetPrimary(ctx, tx, id.TenantID, id.UserID, uid)
			return uid, e
		})
		reply(w, req, out, e)
	})
	type ruleInput struct {
		Kind    string `json:"kind"`
		Pattern string `json:"pattern"`
		Mode    string `json:"mode"`
	}
	h["POST /api/v1/rsm/components/{component_id}/rules"] = write(func() any { return &ruleInput{} }, func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity, body any) {
		in := body.(*ruleInput)
		var out cmdb.Rule
		e := r.rsmWrite(ctx, id, "rule_created", "binding_rule", func(tx pgx.Tx) (string, error) {
			var e error
			out, e = r.CMDB.CreateRule(ctx, tx, id.TenantID, id.UserID, req.PathValue("component_id"), in.Kind, in.Pattern, in.Mode)
			return out.ID, e
		})
		created(w, req, out, e)
	})
	h["POST /api/v1/rsm/rules/{rule_id}/retire"] = write(none, func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity, _ any) {
		uid := req.PathValue("rule_id")
		e := r.rsmWrite(ctx, id, "rule_retired", "binding_rule", func(tx pgx.Tx) (string, error) {
			return uid, r.CMDB.RetireRule(ctx, tx, id.TenantID, id.UserID, uid)
		})
		reply(w, req, map[string]string{"rule_id": uid}, e)
	})
	h["POST /api/v1/rsm/rules/apply"] = write(none, func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity, _ any) {
		long, cancel := context.WithTimeout(context.WithoutCancel(req.Context()), 10*time.Minute) // проход по всем хостам
		defer cancel()
		out, e := r.ApplyRSMRules(long, id, nil)
		reply(w, req, out, e)
	})
	h["GET /api/v1/rsm/proposals"] = read(func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		out, e := r.RSMProposals(ctx, id)
		reply(w, req, out, e)
	})
	h["POST /api/v1/rsm/proposals/{binding_id}/confirm"] = write(none, func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity, _ any) {
		var out cmdb.Binding
		uid := req.PathValue("binding_id")
		e := r.rsmWrite(ctx, id, "proposal_confirmed", "binding", func(tx pgx.Tx) (string, error) {
			var e error
			out, e = r.CMDB.Confirm(ctx, tx, id.TenantID, id.UserID, uid)
			return uid, e
		})
		reply(w, req, out, e)
	})
	h["POST /api/v1/rsm/proposals/{binding_id}/reject"] = write(none, func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity, _ any) {
		uid := req.PathValue("binding_id")
		e := r.rsmWrite(ctx, id, "proposal_rejected", "binding", func(tx pgx.Tx) (string, error) {
			return uid, r.CMDB.Reject(ctx, tx, id.TenantID, id.UserID, uid)
		})
		reply(w, req, map[string]string{"binding_id": uid}, e)
	})
	h["GET /api/v1/rsm/unassigned"] = read(func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity) {
		q, ok := queryOnly(w, req, "cursor", "limit")
		if !ok {
			return
		}
		_, limit, ok := offsetLimit(w, q)
		if !ok {
			return
		}
		out, e := r.RSMUnassigned(ctx, id, q.Get("cursor"), limit)
		reply(w, req, out, e)
	})
	h["GET /api/v1/assets/{asset_uid}/rsm"] = read(func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		out, e := r.AssetRSM(ctx, id, req.PathValue("asset_uid"))
		reply(w, req, out, e)
	})
	h["POST /api/v1/rsm/recompute"] = write(none, func(w http.ResponseWriter, req *http.Request, ctx context.Context, id accessport.Identity, _ any) {
		long, cancel := context.WithTimeout(context.WithoutCancel(req.Context()), 5*time.Minute)
		defer cancel()
		out, e := r.RecomputeRSMState(long, id.TenantID)
		reply(w, req, out, e)
	})
	h["POST /api/v1/rsm/import.csv"] = rsmRoute{"assets:write", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q, ok := queryOnly(w, req, "dry_run")
		if !ok {
			return
		}
		dry := q.Get("dry_run")
		if dry != "true" && dry != "false" {
			access.APIError(w, 400, "INVALID_QUERY")
			return
		}
		if !strings.HasPrefix(req.Header.Get("Content-Type"), "text/csv") {
			access.APIError(w, 415, "UNSUPPORTED_MEDIA_TYPE")
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, req.Body, 8<<20))
		if e != nil {
			access.APIError(w, 413, "PAYLOAD_TOO_LARGE")
			return
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(req.Context()), 5*time.Minute)
		defer cancel()
		id, _ := access.Identity(req.Context())
		out, e := r.ImportRSMCSV(ctx, id, raw, dry == "true")
		reply(w, req, out, e)
	})}
	r.rsmMoreHandlers(h)
	r.hostHandlers(h)
	r.hostRegistryHandlers(h)
	r.platformHandlers(h)
	return h
}
