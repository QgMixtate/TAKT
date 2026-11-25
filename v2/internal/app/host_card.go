package app

// C53.03 — карточка хоста по макету C53-mockups/9: «почему устарело» (состояние хоста, контакт источников, что видит
// обследование сети), разделы профиля (источник, когда собран, состояние), цели сбора («Собрать сейчас», «Проверить
// по WinRM»), путь «система / среда / компонент», показатели шапки (ОС, IP/MAC, домен, площадка, оборудование).

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/cmdb"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

type HostSection struct {
	Name        string     `json:"name"`
	SourceID    *string    `json:"source_id"`
	SourceKind  *string    `json:"source_kind"`
	Acquisition *string    `json:"acquisition"`
	CollectedAt *time.Time `json:"collected_at"`
	Status      string     `json:"status"` // ok | partial | unavailable | unsupported | not_requested | unknown
}

type HostPresenceInfo struct {
	State    string    `json:"state"`
	Network  string    `json:"network_name"`
	IP       string    `json:"ip"`
	Ports    []int32   `json:"ports"`
	LastSeen time.Time `json:"last_seen"`
}

type HostTarget struct {
	ID            string     `json:"target_id"`
	Kind          string     `json:"kind"`
	Address       string     `json:"address"`
	State         string     `json:"state"`
	LastCollected *time.Time `json:"last_collected_at"`
	LastError     *string    `json:"last_error"`
}

type HostOverview struct {
	AssetUID      string             `json:"asset_uid"`
	Name          string             `json:"name"`
	State         *cmdb.HostState    `json:"state"`
	Bindings      []cmdb.BindingPath `json:"bindings"`
	OS            *string            `json:"os"`
	IP            string             `json:"ip"`
	MAC           string             `json:"mac"`
	Domain        string             `json:"domain"`
	Site          string             `json:"site"`
	Hardware      string             `json:"hardware"`
	Sections      []HostSection      `json:"sections"`
	Presence      []HostPresenceInfo `json:"presence"`
	Targets       []HostTarget       `json:"targets"`
	SoftwareCount int                `json:"software_count"`
	TicketsOpen   int                `json:"tickets_open"`
	TicketsTotal  int                `json:"tickets_total"`
}

// sections12 — порядок разделов профиля (как в макете).
var sections12 = []string{"identity", "os", "network", "hardware", "software", "updates", "services", "users_groups", "routes_ports", "resources", "protection", "neighbors"}

func (r *Registry) HostOverview(ctx context.Context, id accessport.Identity, uid string) (HostOverview, error) {
	out := HostOverview{AssetUID: uid, Bindings: []cmdb.BindingPath{}, Sections: []HostSection{}, Presence: []HostPresenceInfo{}, Targets: []HostTarget{}}
	if !identifier.Valid(uid) {
		return out, domain.NotFound
	}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	a, e := r.Assets.Get(ctx, tx, id.TenantID, uid)
	if e != nil {
		return out, e
	}
	list := []*contracts.Asset{&a}
	if e = r.Inventory.EnrichMany(ctx, tx, list); e != nil {
		return out, e
	}
	out.OS = a.OS
	names, e := rsmNames(ctx, tx, id.TenantID, []string{uid})
	if e != nil {
		return out, e
	}
	out.Name = names[uid]
	if s, e := r.CMDB.HostState(ctx, tx, id.TenantID, uid); e == nil {
		out.State = &s
	} else if e != domain.NotFound {
		return out, e
	}
	if out.Bindings, e = r.CMDB.BindingPaths(ctx, tx, id.TenantID, uid, false, 50); e != nil {
		return out, e
	}
	ips, e := rsmIPs(ctx, tx, id.TenantID, []string{uid})
	if e != nil {
		return out, e
	}
	out.IP = ips[uid]
	_ = tx.QueryRow(ctx, `SELECT COALESCE((SELECT m.value #>> '{}' FROM inventory.record_facts12 m LEFT JOIN inventory.record_facts12 n ON n.tenant_id=m.tenant_id AND n.asset_uid=m.asset_uid AND n.section_name='network' AND n.record_key=m.record_key AND n.field_name='name'
WHERE m.tenant_id=$1 AND m.asset_uid=$2 AND m.section_name='network' AND m.field_name='mac' AND jsonb_typeof(m.value)='string' AND m.value #>> '{}' NOT IN ('','00:00:00:00:00:00')
ORDER BY (COALESCE(n.value #>> '{}','') ~* '^(docker|br-|veth|virbr|cni|flannel|cali|tun|lo$|lxc|podman|vethernet)'),m.record_key LIMIT 1),
(SELECT value FROM inventory.current_facts WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='network' AND fact_key LIKE '%.mac' ORDER BY fact_key LIMIT 1),''),
COALESCE((SELECT value #>> '{}' FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='identity' AND field_name='domain' AND jsonb_typeof(value)='string' LIMIT 1),
(SELECT value FROM inventory.current_facts WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='identity' AND fact_key='domain' LIMIT 1),''),
COALESCE((SELECT st.name FROM assets.assets x JOIN scope.sites st ON st.tenant_id=x.tenant_id AND st.site_id=x.site_id WHERE x.tenant_id=$1 AND x.asset_uid=$2),'')`, id.TenantID, uid).Scan(&out.MAC, &out.Domain, &out.Site)
	if out.Hardware, e = hostHardware(ctx, tx, id.TenantID, uid); e != nil {
		return out, e
	}
	if out.Sections, e = hostSections(ctx, tx, id.TenantID, uid); e != nil {
		return out, e
	}
	rows, e := tx.Query(ctx, `SELECT d.state,n.name,host(d.ip),d.ports,d.last_seen FROM sources.discovery_hosts d JOIN sources.discovery_networks n ON n.tenant_id=d.tenant_id AND n.network_id=d.network_id
WHERE d.tenant_id=$1 AND host(d.ip) IN (
SELECT jsonb_array_elements(value)->>'ip' FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='network' AND field_name='addresses' AND jsonb_typeof(value)='array'
UNION SELECT jsonb_array_elements(value::jsonb)->>'ip' FROM inventory.current_facts WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='network' AND fact_key LIKE '%.addresses') ORDER BY d.last_seen DESC LIMIT 10`, id.TenantID, uid)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var p HostPresenceInfo
		if e = rows.Scan(&p.State, &p.Network, &p.IP, &p.Ports, &p.LastSeen); e != nil {
			rows.Close()
			return out, e
		}
		p.LastSeen = p.LastSeen.UTC()
		if p.Ports == nil {
			p.Ports = []int32{}
		}
		out.Presence = append(out.Presence, p)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return out, e
	}
	rows, e = tx.Query(ctx, `SELECT DISTINCT t.target_id::text,t.kind,host(t.address),t.state,t.last_collected_at,t.last_error FROM sources.remote_targets t
JOIN assets.source_records r ON r.tenant_id=t.tenant_id AND r.source_id=t.agent_source_id WHERE t.tenant_id=$1 AND r.asset_uid=$2 ORDER BY 2,3`, id.TenantID, uid)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var t HostTarget
		if e = rows.Scan(&t.ID, &t.Kind, &t.Address, &t.State, &t.LastCollected, &t.LastError); e != nil {
			rows.Close()
			return out, e
		}
		out.Targets = append(out.Targets, t)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return out, e
	}
	if e = tx.QueryRow(ctx, `SELECT (SELECT count(DISTINCT record_key) FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='software')
+(SELECT count(*) FROM inventory.current_facts WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='software')`, id.TenantID, uid).Scan(&out.SoftwareCount); e != nil {
		return out, e
	}
	if out.TicketsOpen, out.TicketsTotal, e = rsmTicketCounts(ctx, tx, id.TenantID, "asset", uid); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

// hostHardware — «Оборудование»: производитель и модель, число процессоров/ядер, память (1.2 и 1.0).
func hostHardware(ctx context.Context, tx pgx.Tx, tenant, uid string) (string, error) {
	rows, e := tx.Query(ctx, `SELECT record_key,field_name,value #>> '{}' FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='hardware' AND jsonb_typeof(value) IN ('string','number') LIMIT 2000`, tenant, uid)
	if e != nil {
		return "", e
	}
	recs := map[string]map[string]string{}
	for rows.Next() {
		var k, f, v string
		if e = rows.Scan(&k, &f, &v); e != nil {
			rows.Close()
			return "", e
		}
		if recs[k] == nil {
			recs[k] = map[string]string{}
		}
		recs[k][f] = v
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return "", e
	}
	vendor, model, cpus, mem := "", "", 0, int64(0)
	// модель — из записи «system», затем «baseboard»; у «bios» в model лежит версия прошивки (ISSUES №82)
	rank, best := map[string]int{"system": 3, "baseboard": 2, "bios": 1}, 0
	for _, r := range recs {
		switch r["kind"] {
		case "bios", "system", "baseboard":
			v, m := r["vendor"], r["model"]
			if r["kind"] == "bios" {
				// №89: у разных сборщиков в записи bios лежит то модель ПК («VMware Virtual Platform»), то версия прошивки
				// («N.1.08ADA03») и производитель BIOS («American Megatrends»): версию и производителя BIOS не показываем
				if !strings.Contains(strings.TrimSpace(m), " ") {
					m = ""
				}
				if biosVendor(v) {
					v = ""
				}
			}
			if rk := rank[r["kind"]]; rk > best && (m != "" || v != "") {
				best, vendor, model = rk, v, m
			}
		case "cpu", "processor":
			cpus++
		case "memory":
			var n int64
			for _, c := range r["bytes"] {
				if c < '0' || c > '9' {
					n = 0
					break
				}
				n = n*10 + int64(c-'0')
			}
			mem += n
		}
	}
	parts := []string{}
	if s := strings.TrimSpace(vendor + " " + model); s != "" {
		parts = append(parts, s)
	}
	if cpus > 0 {
		parts = append(parts, itoa(cpus)+" CPU")
	}
	if mem > 0 {
		parts = append(parts, itoa(int((mem+(1<<29))>>30))+" ГБ")
	}
	return strings.Join(parts, " · "), nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

// hostSections — разделы профиля: по каждому разделу последний сбор (источник, время, состояние) — 1.2 и 1.0.
func hostSections(ctx context.Context, tx pgx.Tx, tenant, uid string) ([]HostSection, error) {
	by := map[string]HostSection{}
	rows, e := tx.Query(ctx, `SELECT DISTINCT ON (x.section_name) x.section_name,x.source_id::text,s.source_kind,(SELECT r.kind FROM sources.remote_targets r WHERE r.tenant_id=s.tenant_id AND r.agent_source_id=s.source_id LIMIT 1),x.collected_at,x.last_status
FROM inventory.record_section_source_state12 x JOIN sources.sources s ON s.tenant_id=x.tenant_id AND s.source_id=x.source_id
WHERE x.tenant_id=$1 AND x.asset_uid=$2 ORDER BY x.section_name,x.collected_at DESC`, tenant, uid)
	if e != nil {
		return nil, e
	}
	for rows.Next() {
		var h HostSection
		if e = rows.Scan(&h.Name, &h.SourceID, &h.SourceKind, &h.Acquisition, &h.CollectedAt, &h.Status); e != nil {
			rows.Close()
			return nil, e
		}
		by[h.Name] = h
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return nil, e
	}
	rows, e = tx.Query(ctx, `SELECT s.section_name,o.source_id::text,src.source_kind,o.collected_at,s.last_status FROM inventory.section_state s
LEFT JOIN inventory.observations o ON o.tenant_id=s.tenant_id AND o.observation_id=COALESCE(s.last_success_id,s.last_attempt_id)
LEFT JOIN sources.sources src ON src.tenant_id=o.tenant_id AND src.source_id=o.source_id WHERE s.tenant_id=$1 AND s.asset_uid=$2`, tenant, uid)
	if e != nil {
		return nil, e
	}
	for rows.Next() {
		var h HostSection
		if e = rows.Scan(&h.Name, &h.SourceID, &h.SourceKind, &h.CollectedAt, &h.Status); e != nil {
			rows.Close()
			return nil, e
		}
		// №88: раздел, собранный одним источником, не перекрывается более свежим «не поддерживается» другого источника
		// (агент собрал 12 разделов, WinRM — 6): берём собранный, а среди собранных — самый свежий
		got := func(x HostSection) bool { return x.Status == "ok" || x.Status == "partial" }
		if cur, ok := by[h.Name]; !ok || (got(h) && !got(cur)) || (got(h) == got(cur) && h.CollectedAt != nil && (cur.CollectedAt == nil || h.CollectedAt.After(*cur.CollectedAt))) {
			by[h.Name] = h
		}
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return nil, e
	}
	out := []HostSection{}
	for _, n := range sections12 {
		h, ok := by[n]
		if !ok {
			h = HostSection{Name: n, Status: "unknown"}
		}
		if h.CollectedAt != nil {
			t := h.CollectedAt.UTC()
			h.CollectedAt = &t
		}
		out = append(out, h)
	}
	return out, nil
}

// hostHandlers — маршруты карточки хоста (в таблице РСМ: модуль включается целиком).
func (r *Registry) hostHandlers(h map[string]rsmRoute) {
	h["GET /api/v1/assets/{asset_uid}/overview"] = rsmRoute{"assets:read", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		out, e := r.HostOverview(ctx, id, req.PathValue("asset_uid"))
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, out)
	})}
	h["GET /api/v1/assets/{asset_uid}/tickets"] = rsmRoute{"assets:read", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		out, e := r.RSMTickets(ctx, id, "asset", req.PathValue("asset_uid"))
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, out)
	})}
	h["POST /api/v1/assets/{asset_uid}/collect"] = rsmRoute{"assets:write", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body struct{}
		if !readOperationBody(w, req, &body) {
			return
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		out, e := r.RSMCollect(ctx, id, "asset", req.PathValue("asset_uid"))
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, out)
	})}
}

func biosVendor(v string) bool {
	l := strings.ToLower(v)
	for _, b := range []string{"american megatrends", "ami", "phoenix", "insyde", "award", "seabios", "edk ii", "tianocore"} {
		if strings.HasPrefix(l, b) {
			return true
		}
	}
	return false
}
