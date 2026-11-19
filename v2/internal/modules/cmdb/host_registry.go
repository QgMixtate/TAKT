package cmdb

import (
	"context"
	"encoding/json"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

// C53.04 — проекция реестра хостов (cmdb.host_registry): строится приложением из активов, инвентаризации,
// ответственности и привязок РСМ; здесь — запись пачками, страница с фильтрами и сортировкой, счётчики и дерево.

type HostRegistryRow struct {
	AssetUID       string     `json:"asset_uid"`
	Name           string     `json:"name"`
	IP             string     `json:"ip"`
	OS             string     `json:"os"`
	OSFamily       string     `json:"os_family"`
	Class          string     `json:"asset_class"`
	SiteID         string     `json:"site_id"`
	SiteName       string     `json:"site_name"`
	Segment        string     `json:"segment"`
	AccountableID  *string    `json:"accountable_id"`
	Accountable    string     `json:"accountable_name"`
	Team           string     `json:"team_name"`
	SiteFallback   bool       `json:"site_fallback"`
	SystemUID      *string    `json:"system_uid"`
	System         string     `json:"system_name"`
	Component      string     `json:"component_name"`
	SectionsOK     int        `json:"sections_ok"`
	SectionsTotal  int        `json:"sections_total"`
	Sources        []string   `json:"sources"`
	Freshness      string     `json:"freshness"`
	LastInventory  *time.Time `json:"last_inventory_at"`
	CreatedAt      time.Time  `json:"created_at"`
	ComputedAt     time.Time  `json:"computed_at"`
	AggregateState string     `json:"-"`
}

// SaveHostRegistry — upsert пачки строк (до 2000) одним запросом.
func (Store) SaveHostRegistry(ctx context.Context, tx pgx.Tx, tenant string, rows []HostRegistryRow) error {
	if len(rows) == 0 {
		return nil
	}
	if len(rows) > 2000 {
		return domain.Invalid
	}
	raw, e := json.Marshal(rows)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO cmdb.host_registry(tenant_id,asset_uid,name,name_key,ip,os,os_family,asset_class,site_id,site_name,segment,accountable_id,accountable_name,team_name,site_fallback,system_uid,system_name,component_name,sections_ok,sections_total,sources,freshness,last_inventory_at,created_at,computed_at)
SELECT $1,x.asset_uid,x.name,lower(x.name),x.ip,x.os,x.os_family,x.asset_class,x.site_id,x.site_name,x.segment,x.accountable_id,x.accountable_name,x.team_name,x.site_fallback,x.system_uid,x.system_name,x.component_name,x.sections_ok,x.sections_total,COALESCE(x.sources,'{}'),x.freshness,x.last_inventory_at,x.created_at,x.computed_at
FROM jsonb_to_recordset($2::jsonb) AS x(asset_uid uuid,name text,ip text,os text,os_family text,asset_class text,site_id uuid,site_name text,segment text,accountable_id uuid,accountable_name text,team_name text,site_fallback boolean,system_uid uuid,system_name text,component_name text,sections_ok int,sections_total int,sources text[],freshness text,last_inventory_at timestamptz,created_at timestamptz,computed_at timestamptz)
WHERE EXISTS(SELECT 1 FROM assets.assets a WHERE a.tenant_id=$1 AND a.asset_uid=x.asset_uid)
ON CONFLICT (tenant_id,asset_uid) DO UPDATE SET name=excluded.name,name_key=excluded.name_key,ip=excluded.ip,os=excluded.os,os_family=excluded.os_family,asset_class=excluded.asset_class,site_id=excluded.site_id,site_name=excluded.site_name,segment=excluded.segment,
accountable_id=excluded.accountable_id,accountable_name=excluded.accountable_name,team_name=excluded.team_name,site_fallback=excluded.site_fallback,system_uid=excluded.system_uid,system_name=excluded.system_name,component_name=excluded.component_name,
sections_ok=excluded.sections_ok,sections_total=excluded.sections_total,sources=excluded.sources,freshness=excluded.freshness,last_inventory_at=excluded.last_inventory_at,created_at=excluded.created_at,computed_at=excluded.computed_at`, tenant, string(raw))
	return e
}

// PruneHostRegistry — убрать строки активов, которых больше нет в реестре (слиты, выведены), или не обновлённые
// полным пересчётом, начатым в since.
func (Store) PruneHostRegistry(ctx context.Context, tx pgx.Tx, tenant string, since time.Time) error {
	_, e := tx.Exec(ctx, `DELETE FROM cmdb.host_registry h WHERE h.tenant_id=$1 AND (h.computed_at<$2 OR EXISTS(SELECT 1 FROM assets.assets a WHERE a.tenant_id=h.tenant_id AND a.asset_uid=h.asset_uid AND (a.merged_into IS NOT NULL OR a.retired_at IS NOT NULL)))`, tenant, since)
	return e
}

// RemoveHostRegistry — точечно убрать строки (слитые/выведенные при точечном обновлении).
func (Store) RemoveHostRegistry(ctx context.Context, tx pgx.Tx, tenant string, uids []string) error {
	if len(uids) == 0 {
		return nil
	}
	_, e := tx.Exec(ctx, `DELETE FROM cmdb.host_registry WHERE tenant_id=$1 AND asset_uid=ANY($2::uuid[])`, tenant, uids)
	return e
}

// HostRegistryClasses — прежние класс и время инвентаризации (чтобы не пересчитывать наблюдаемый класс без изменений).
func (Store) HostRegistryClasses(ctx context.Context, tx pgx.Tx, tenant string, uids []string) (map[string]HostRegistryRow, error) {
	out := map[string]HostRegistryRow{}
	rows, e := tx.Query(ctx, `SELECT asset_uid::text,asset_class,last_inventory_at FROM cmdb.host_registry WHERE tenant_id=$1 AND asset_uid=ANY($2::uuid[])`, tenant, uids)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var r HostRegistryRow
		if e = rows.Scan(&r.AssetUID, &r.Class, &r.LastInventory); e != nil {
			return nil, e
		}
		out[r.AssetUID] = r
	}
	return out, rows.Err()
}

// HostFilter — фильтры плотного реестра. Пустое поле — без ограничения.
type HostFilter struct {
	Query     string
	Site      string
	Segment   string
	Class     string
	OSFamily  string
	OS        string
	Owner     string // subject_id; "none" — резервная команда площадки (без назначенного ответственного)
	Team      string
	System    string // service_uid; "none" — вне систем
	Component string
	Freshness string // fresh|stale|unknown|partial
	Sort      string // name|ip|os|freshness|owner|system|last
	Desc      bool
	Offset    int
	Limit     int
}

var hostSorts = map[string]bool{"name": true, "ip": true, "os": true, "freshness": true, "owner": true, "system": true, "last": true}

func (f HostFilter) valid() bool {
	okUUID := func(v string) bool { return v == "" || identifier.Valid(v) }
	return len(f.Query) <= 200 && len(f.Segment) <= 256 && len(f.Class) <= 64 && len(f.OS) <= 512 && len(f.Team) <= 256 && len(f.Component) <= 256 &&
		okUUID(f.Site) && (f.Owner == "none" || okUUID(f.Owner)) && (f.System == "none" || okUUID(f.System)) &&
		(f.OSFamily == "" || f.OSFamily == "windows" || f.OSFamily == "linux" || f.OSFamily == "macos" || f.OSFamily == "network" || f.OSFamily == "other" || f.OSFamily == "unknown") &&
		(f.Freshness == "" || f.Freshness == "fresh" || f.Freshness == "stale" || f.Freshness == "unknown" || f.Freshness == "partial") &&
		(f.Sort == "" || hostSorts[f.Sort]) && f.Offset >= 0 && f.Offset <= 1000000
}

// hostWhere — общий литеральный фрагмент условия ($1 tenant, $2..$12 фильтры); подставляется в запросы как есть.
// Условие фильтра ($1 tenant, $2..$12) повторено литералом в каждом запросе: динамический SQL в модулях запрещён.

func (f HostFilter) args(tenant string) []any {
	return []any{tenant, f.Query, f.Site, f.Segment, f.Class, f.OSFamily, f.OS, f.Owner, f.Team, f.System, f.Component, f.Freshness}
}

// HostRegistryPage — страница строк и число строк по фильтру.
func (Store) HostRegistryPage(ctx context.Context, tx pgx.Tx, tenant string, f HostFilter) ([]HostRegistryRow, int, error) {
	if !f.valid() {
		return nil, 0, domain.Invalid
	}
	if f.Limit != 100 && f.Limit != 250 && f.Limit != 500 {
		f.Limit = 100
	}
	if f.Sort == "" {
		f.Sort = "name"
	}
	args := append(f.args(tenant), f.Sort, f.Desc, f.Offset, f.Limit)
	rows, e := tx.Query(ctx, `SELECT h.asset_uid::text,h.name,h.ip,h.os,h.os_family,h.asset_class,h.site_id::text,h.site_name,h.segment,h.accountable_id::text,h.accountable_name,h.team_name,h.site_fallback,
h.system_uid::text,h.system_name,h.component_name,h.sections_ok,h.sections_total,h.sources,h.freshness,h.last_inventory_at,h.created_at,h.computed_at,count(*) OVER ()
FROM cmdb.host_registry h WHERE h.tenant_id=$1
AND ($2='' OR strpos(h.name_key,lower($2))>0 OR strpos(h.ip,$2)>0 OR strpos(lower(h.os),lower($2))>0)
AND ($3='' OR h.site_id::text=$3) AND ($4='' OR h.segment=$4) AND ($5='' OR h.asset_class=$5) AND ($6='' OR h.os_family=$6) AND ($7='' OR h.os=$7)
AND ($8='' OR ($8='none' AND h.site_fallback) OR h.accountable_id::text=$8) AND ($9='' OR h.team_name=$9)
AND ($10='' OR ($10='none' AND h.system_uid IS NULL) OR h.system_uid::text=$10) AND ($11='' OR h.component_name=$11)
AND ($12='' OR ($12='partial' AND h.freshness='fresh' AND h.sections_ok<h.sections_total) OR h.freshness=$12)
ORDER BY
 CASE WHEN NOT $14 AND $13='name' THEN h.name_key END ASC, CASE WHEN $14 AND $13='name' THEN h.name_key END DESC,
 CASE WHEN NOT $14 AND $13='ip' THEN h.ip END ASC, CASE WHEN $14 AND $13='ip' THEN h.ip END DESC,
 CASE WHEN NOT $14 AND $13='os' THEN h.os END ASC, CASE WHEN $14 AND $13='os' THEN h.os END DESC,
 CASE WHEN NOT $14 AND $13='freshness' THEN h.freshness END ASC, CASE WHEN $14 AND $13='freshness' THEN h.freshness END DESC,
 CASE WHEN NOT $14 AND $13='owner' THEN h.accountable_name END ASC, CASE WHEN $14 AND $13='owner' THEN h.accountable_name END DESC,
 CASE WHEN NOT $14 AND $13='system' THEN h.system_name END ASC, CASE WHEN $14 AND $13='system' THEN h.system_name END DESC,
 CASE WHEN NOT $14 AND $13='last' THEN h.last_inventory_at END ASC NULLS FIRST, CASE WHEN $14 AND $13='last' THEN h.last_inventory_at END DESC NULLS LAST,
 h.name_key,h.asset_uid OFFSET $15 LIMIT $16`, args...)
	if e != nil {
		return nil, 0, e
	}
	defer rows.Close()
	out, total := []HostRegistryRow{}, 0
	for rows.Next() {
		var r HostRegistryRow
		if e = rows.Scan(&r.AssetUID, &r.Name, &r.IP, &r.OS, &r.OSFamily, &r.Class, &r.SiteID, &r.SiteName, &r.Segment, &r.AccountableID, &r.Accountable, &r.Team, &r.SiteFallback,
			&r.SystemUID, &r.System, &r.Component, &r.SectionsOK, &r.SectionsTotal, &r.Sources, &r.Freshness, &r.LastInventory, &r.CreatedAt, &r.ComputedAt, &total); e != nil {
			return nil, 0, e
		}
		out = append(out, r)
	}
	if e = rows.Err(); e != nil {
		return nil, 0, e
	}
	if len(out) == 0 && f.Offset == 0 {
		total = 0
	} else if len(out) == 0 {
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM cmdb.host_registry h WHERE h.tenant_id=$1
AND ($2='' OR strpos(h.name_key,lower($2))>0 OR strpos(h.ip,$2)>0 OR strpos(lower(h.os),lower($2))>0)
AND ($3='' OR h.site_id::text=$3) AND ($4='' OR h.segment=$4) AND ($5='' OR h.asset_class=$5) AND ($6='' OR h.os_family=$6) AND ($7='' OR h.os=$7)
AND ($8='' OR ($8='none' AND h.site_fallback) OR h.accountable_id::text=$8) AND ($9='' OR h.team_name=$9)
AND ($10='' OR ($10='none' AND h.system_uid IS NULL) OR h.system_uid::text=$10) AND ($11='' OR h.component_name=$11)
AND ($12='' OR ($12='partial' AND h.freshness='fresh' AND h.sections_ok<h.sections_total) OR h.freshness=$12)`, f.args(tenant)...).Scan(&total); e != nil {
			return nil, 0, e
		}
	}
	return out, total, nil
}

// HostRegistryUIDs — все хосты по фильтру (для «выбрать все по фильтру»; не больше limit).
func (Store) HostRegistryUIDs(ctx context.Context, tx pgx.Tx, tenant string, f HostFilter, limit int) ([]string, error) {
	if !f.valid() {
		return nil, domain.Invalid
	}
	rows, e := tx.Query(ctx, `SELECT h.asset_uid::text FROM cmdb.host_registry h WHERE h.tenant_id=$1
AND ($2='' OR strpos(h.name_key,lower($2))>0 OR strpos(h.ip,$2)>0 OR strpos(lower(h.os),lower($2))>0)
AND ($3='' OR h.site_id::text=$3) AND ($4='' OR h.segment=$4) AND ($5='' OR h.asset_class=$5) AND ($6='' OR h.os_family=$6) AND ($7='' OR h.os=$7)
AND ($8='' OR ($8='none' AND h.site_fallback) OR h.accountable_id::text=$8) AND ($9='' OR h.team_name=$9)
AND ($10='' OR ($10='none' AND h.system_uid IS NULL) OR h.system_uid::text=$10) AND ($11='' OR h.component_name=$11)
AND ($12='' OR ($12='partial' AND h.freshness='fresh' AND h.sections_ok<h.sections_total) OR h.freshness=$12) ORDER BY h.name_key,h.asset_uid LIMIT $13`, append(f.args(tenant), limit)...)
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

// HostCounters — полоса счётчиков реестра (по всем хостам, без фильтра).
type HostCounters struct {
	Total      int        `json:"total"`
	Fresh      int        `json:"fresh"`
	Partial    int        `json:"partial"`
	Stale      int        `json:"stale"`
	Unknown    int        `json:"unknown"`
	NoOwner    int        `json:"without_owner"`
	New7d      int        `json:"new_7d"`
	ComputedAt *time.Time `json:"computed_at"`
}

func (Store) HostRegistryCounters(ctx context.Context, tx pgx.Tx, tenant string) (HostCounters, error) {
	var c HostCounters
	e := tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE freshness='fresh'),count(*) FILTER (WHERE freshness='fresh' AND sections_ok<sections_total),count(*) FILTER (WHERE freshness='stale'),
count(*) FILTER (WHERE freshness='unknown'),count(*) FILTER (WHERE site_fallback),count(*) FILTER (WHERE created_at>now()-interval '7 days'),max(computed_at)
FROM cmdb.host_registry WHERE tenant_id=$1`, tenant).Scan(&c.Total, &c.Fresh, &c.Partial, &c.Stale, &c.Unknown, &c.NoOwner, &c.New7d, &c.ComputedAt)
	return c, e
}

// HostTreeNode — узел дерева группировки (два уровня) с числом хостов.
type HostTreeNode struct {
	Key      string         `json:"key"`
	Label    string         `json:"label"`
	Count    int            `json:"count"`
	Children []HostTreeNode `json:"children"`
}

// HostRegistryTree — дерево: site (площадка → сегмент), owner (команда → ответственный), system (система → компонент),
// os (семейство → версия). Ключи узлов — значения фильтров (site_id/segment, team/owner_id, system_uid/component, family/os).
func (Store) HostRegistryTree(ctx context.Context, tx pgx.Tx, tenant, by string) ([]HostTreeNode, error) {
	var rows pgx.Rows
	var e error
	switch by {
	case "site":
		rows, e = tx.Query(ctx, `SELECT site_id::text,site_name,segment,segment,count(*) FROM cmdb.host_registry WHERE tenant_id=$1 GROUP BY 1,2,3,4 ORDER BY 2,3`, tenant)
	case "owner":
		rows, e = tx.Query(ctx, `SELECT team_name,team_name,COALESCE(accountable_id::text,''),accountable_name,count(*) FROM cmdb.host_registry WHERE tenant_id=$1 GROUP BY 1,2,3,4 ORDER BY 2,4`, tenant)
	case "system":
		rows, e = tx.Query(ctx, `SELECT COALESCE(system_uid::text,'none'),system_name,component_name,component_name,count(*) FROM cmdb.host_registry WHERE tenant_id=$1 GROUP BY 1,2,3,4 ORDER BY 2,3`, tenant)
	case "os":
		rows, e = tx.Query(ctx, `SELECT os_family,os_family,os,os,count(*) FROM cmdb.host_registry WHERE tenant_id=$1 GROUP BY 1,2,3,4 ORDER BY 2,3`, tenant)
	default:
		return nil, domain.Invalid
	}
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []HostTreeNode{}
	index := map[string]int{}
	for rows.Next() {
		var k1, l1, k2, l2 string
		var n int
		if e = rows.Scan(&k1, &l1, &k2, &l2, &n); e != nil {
			return nil, e
		}
		i, ok := index[k1]
		if !ok {
			i = len(out)
			index[k1] = i
			out = append(out, HostTreeNode{Key: k1, Label: l1, Children: []HostTreeNode{}})
		}
		out[i].Count += n
		out[i].Children = append(out[i].Children, HostTreeNode{Key: k2, Label: l2, Count: n, Children: []HostTreeNode{}})
	}
	return out, rows.Err()
}
