package cmdb

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

// C57.01 — снимки платформ (контракт contracts/c57-platform.schema.json, C03 не меняется): экземпляр платформы,
// объекты и связи. Сопоставление объекта с активом — по BIOS UUID (обе формы порядка байт VMware) или серийному номеру.

type PlatformObject struct {
	Ref      string         `json:"ref"`
	Kind     string         `json:"kind"`
	Name     string         `json:"name"`
	BiosUUID *string        `json:"bios_uuid"`
	Serial   *string        `json:"serial"`
	Hostname *string        `json:"hostname"`
	MACs     []string       `json:"macs"`
	Attrs    map[string]any `json:"attrs"`
}

type PlatformRelation struct {
	From string `json:"from"`
	Type string `json:"type"`
	To   string `json:"to"`
}

type PlatformSnapshot struct {
	Major        int                `json:"major"`
	SnapshotID   string             `json:"snapshot_id"`
	Tenant       string             `json:"tenant_id"`
	Source       string             `json:"source_id"`
	Generation   string             `json:"generation_id"`
	Target       *string            `json:"target_id"`
	Platform     string             `json:"platform"`
	Instance     string             `json:"instance"`
	InstanceName string             `json:"instance_name"`
	CollectedAt  time.Time          `json:"collected_at"`
	Complete     bool               `json:"complete"`
	Objects      []PlatformObject   `json:"objects"`
	Relations    []PlatformRelation `json:"relations"`
	Errors       []string           `json:"errors"`
}

type PlatformSnapshotResult struct {
	SnapshotID string `json:"snapshot_id"`
	InstanceID string `json:"instance_id"`
	Duplicate  bool   `json:"duplicate"`
	Objects    int    `json:"objects"`
	Matched    int    `json:"matched"`
	Removed    int    `json:"removed"`
}

var (
	platformKinds     = map[string]bool{"kvm": true, "vsphere": true, "ovirt": true, "redfish": true, "ad": true, "hyperv": true, "proxmox": true}
	platformObjKinds  = map[string]bool{"datacenter": true, "cluster": true, "host": true, "vm": true, "datastore": true, "network": true, "pool": true, "chassis": true, "bmc": true, "computer": true}
	platformRelations = map[string]bool{"runs_on": true, "member_of": true, "uses_storage": true, "connected_to": true, "located_in": true, "managed_by": true}
	attrName          = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)
)

// PlatformMissingLimit — после стольких полных снимков подряд без объекта он «удалён из платформы».
const PlatformMissingLimit = 3

// ValidatePlatformSnapshot — проверка снимка до записи (схема C57 — та же, здесь — для машинного канала).
func ValidatePlatformSnapshot(s PlatformSnapshot) error {
	if s.Major != 1 || !identifier.Valid(s.SnapshotID) || !identifier.Valid(s.Tenant) || !identifier.Valid(s.Source) || !identifier.Valid(s.Generation) ||
		(s.Target != nil && !identifier.Valid(*s.Target)) || !platformKinds[s.Platform] || s.Instance == "" || len(s.Instance) > 256 || len(s.InstanceName) > 256 ||
		s.CollectedAt.IsZero() || s.CollectedAt.After(time.Now().Add(10*time.Minute)) || len(s.Objects) > 20000 || len(s.Relations) > 50000 || len(s.Errors) > 32 {
		return domain.Invalid
	}
	refs := make(map[string]bool, len(s.Objects))
	for _, o := range s.Objects {
		if o.Ref == "" || len(o.Ref) > 256 || refs[o.Ref] || !platformObjKinds[o.Kind] || len(o.Name) > 256 || len(o.MACs) > 32 || len(o.Attrs) > 64 {
			return domain.Invalid
		}
		refs[o.Ref] = true
		for k, v := range o.Attrs {
			if !attrName.MatchString(k) {
				return domain.Invalid
			}
			switch x := v.(type) {
			case nil, bool, float64, json.Number:
			case string:
				if len(x) > 1024 {
					return domain.Invalid
				}
			default:
				return domain.Invalid
			}
		}
	}
	for _, r := range s.Relations {
		if !platformRelations[r.Type] || !refs[r.From] || !refs[r.To] {
			return domain.Invalid
		}
	}
	for _, e := range s.Errors {
		if len(e) > 64 {
			return domain.Invalid
		}
	}
	return nil
}

// BiosUUIDForms — каноническая форма BIOS UUID и форма с переставленными байтами первых трёх групп (VMware отдаёт
// UUID ВМ в API в одном порядке, а гость видит SMBIOS UUID в другом). Неверный UUID — пустой список.
func BiosUUIDForms(v string) []string {
	v = strings.ToLower(strings.TrimSpace(v))
	if !identifier.Valid(v) {
		return nil
	}
	switch v {
	case "00000000-0000-0000-0000-000000000000", "ffffffff-ffff-ffff-ffff-ffffffffffff", "03000200-0400-0500-0006-000700080009":
		return nil
	}
	raw, e := hex.DecodeString(strings.ReplaceAll(v, "-", ""))
	if e != nil || len(raw) != 16 {
		return nil
	}
	sw := append([]byte{}, raw...)
	sw[0], sw[1], sw[2], sw[3] = raw[3], raw[2], raw[1], raw[0]
	sw[4], sw[5] = raw[5], raw[4]
	sw[6], sw[7] = raw[7], raw[6]
	h := hex.EncodeToString(sw)
	swapped := h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
	if swapped == v {
		return []string{v}
	}
	return []string{v, swapped}
}

func platformSerial(p *string) string {
	if p == nil {
		return ""
	}
	v := strings.TrimSpace(*p)
	switch strings.ToLower(v) {
	case "", "0", "none", "n/a", "na", "null", "default string", "to be filled by o.e.m.", "system serial number", "not specified", "not applicable", "123456789", "0123456789", "invalid":
		return ""
	}
	if strings.Trim(v, "0") == "" || len(v) < 4 {
		return ""
	}
	return v
}

// SavePlatformSnapshot записывает снимок: экземпляр, объекты, связи; сопоставляет объекты с активами; для полного
// снимка — счётчик пропусков и «удалён из платформы». Повтор того же snapshot_id ничего не меняет.
func (Store) SavePlatformSnapshot(ctx context.Context, tx pgx.Tx, s PlatformSnapshot) (PlatformSnapshotResult, error) {
	out := PlatformSnapshotResult{SnapshotID: s.SnapshotID, Objects: len(s.Objects)}
	if e := ValidatePlatformSnapshot(s); e != nil {
		return out, e
	}
	errs, _ := json.Marshal(append([]string{}, s.Errors...))
	e := tx.QueryRow(ctx, `INSERT INTO cmdb.platform_instances(tenant_id,instance_id,platform,instance_key,name,source_id,target_id,last_snapshot_at,last_complete_at,errors)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,CASE WHEN $9 THEN $8::timestamptz END,$10)
ON CONFLICT (tenant_id,platform,instance_key) DO UPDATE SET name=excluded.name,source_id=excluded.source_id,target_id=excluded.target_id,
 last_snapshot_at=GREATEST(cmdb.platform_instances.last_snapshot_at,excluded.last_snapshot_at),
 last_complete_at=CASE WHEN $9 THEN GREATEST(cmdb.platform_instances.last_complete_at,excluded.last_snapshot_at) ELSE cmdb.platform_instances.last_complete_at END,
 errors=excluded.errors
RETURNING instance_id::text`, s.Tenant, identifier.New(), s.Platform, s.Instance, s.InstanceName, s.Source, s.Target, s.CollectedAt, s.Complete, string(errs)).Scan(&out.InstanceID)
	if e != nil {
		return out, e
	}
	tag, e := tx.Exec(ctx, `INSERT INTO cmdb.platform_snapshots(tenant_id,snapshot_id,instance_id,collected_at,complete,objects) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
		s.Tenant, s.SnapshotID, out.InstanceID, s.CollectedAt, s.Complete, len(s.Objects))
	if e != nil {
		return out, e
	}
	if tag.RowsAffected() == 0 {
		out.Duplicate = true
		return out, nil
	}
	type row struct {
		Ref      string         `json:"ref"`
		Kind     string         `json:"kind"`
		Name     string         `json:"name"`
		Bios     []string       `json:"bios"`
		Serial   string         `json:"serial"`
		Hostname string         `json:"hostname"`
		MACs     []string       `json:"macs"`
		Attrs    map[string]any `json:"attrs"`
	}
	rows := make([]row, 0, len(s.Objects))
	for _, o := range s.Objects {
		r := row{Ref: o.Ref, Kind: o.Kind, Name: o.Name, Serial: platformSerial(o.Serial), MACs: o.MACs, Attrs: o.Attrs}
		if o.BiosUUID != nil {
			r.Bios = BiosUUIDForms(*o.BiosUUID)
		}
		if o.Hostname != nil {
			r.Hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(*o.Hostname), "."))
		}
		if r.MACs == nil {
			r.MACs = []string{}
		}
		if r.Attrs == nil {
			r.Attrs = map[string]any{}
		}
		if r.Bios == nil {
			r.Bios = []string{}
		}
		rows = append(rows, r)
	}
	payload, e := json.Marshal(rows)
	if e != nil {
		return out, e
	}
	// сопоставление: BIOS UUID (любая из форм), иначе серийный номер; только действующие активы
	if _, e = tx.Exec(ctx, `INSERT INTO cmdb.platform_objects(tenant_id,instance_id,ref,kind,name,bios_uuid,serial,hostname,macs,attrs,asset_uid,first_seen,last_seen)
SELECT $1,$2,x.ref,x.kind,x.name,NULLIF(x.bios->>0,''),NULLIF(x.serial,''),NULLIF(x.hostname,''),ARRAY(SELECT jsonb_array_elements_text(x.macs)),x.attrs,
 COALESCE(
  (SELECT i.asset_uid FROM assets.asset_identifiers i JOIN assets.assets a ON a.tenant_id=i.tenant_id AND a.asset_uid=i.asset_uid AND a.merged_into IS NULL AND a.retired_at IS NULL
   WHERE i.tenant_id=$1 AND i.kind IN ('bios_uuid','machine_uuid') AND i.valid_to IS NULL AND i.normalized_value IN (SELECT jsonb_array_elements_text(x.bios)) ORDER BY i.valid_from LIMIT 1),
  (SELECT i.asset_uid FROM assets.asset_identifiers i JOIN assets.assets a ON a.tenant_id=i.tenant_id AND a.asset_uid=i.asset_uid AND a.merged_into IS NULL AND a.retired_at IS NULL
   WHERE i.tenant_id=$1 AND i.kind='serial' AND i.valid_to IS NULL AND x.serial<>'' AND lower(i.normalized_value)=lower(x.serial) ORDER BY i.valid_from LIMIT 1)),
 $3,$3
FROM jsonb_to_recordset($4::jsonb) AS x(ref text,kind text,name text,bios jsonb,serial text,hostname text,macs jsonb,attrs jsonb)
ON CONFLICT (tenant_id,instance_id,ref) DO UPDATE SET kind=excluded.kind,name=excluded.name,bios_uuid=excluded.bios_uuid,serial=excluded.serial,hostname=excluded.hostname,
 macs=excluded.macs,attrs=excluded.attrs,asset_uid=excluded.asset_uid,last_seen=GREATEST(cmdb.platform_objects.last_seen,excluded.last_seen),missing_snapshots=0,removed_at=NULL`,
		s.Tenant, out.InstanceID, s.CollectedAt, string(payload)); e != nil {
		return out, e
	}
	rels, e := json.Marshal(s.Relations)
	if e != nil {
		return out, e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO cmdb.platform_relations(tenant_id,instance_id,from_ref,rel_type,to_ref,last_seen)
SELECT $1,$2,x."from",x."type",x."to",$3 FROM jsonb_to_recordset($4::jsonb) AS x("from" text,"type" text,"to" text)
ON CONFLICT (tenant_id,instance_id,from_ref,rel_type,to_ref) DO UPDATE SET last_seen=GREATEST(cmdb.platform_relations.last_seen,excluded.last_seen)`,
		s.Tenant, out.InstanceID, s.CollectedAt, string(rels)); e != nil {
		return out, e
	}
	if s.Complete {
		if _, e = tx.Exec(ctx, `DELETE FROM cmdb.platform_relations WHERE tenant_id=$1 AND instance_id=$2 AND last_seen<$3`, s.Tenant, out.InstanceID, s.CollectedAt); e != nil {
			return out, e
		}
		if _, e = tx.Exec(ctx, `UPDATE cmdb.platform_objects SET missing_snapshots=missing_snapshots+1 WHERE tenant_id=$1 AND instance_id=$2 AND last_seen<$3 AND removed_at IS NULL`, s.Tenant, out.InstanceID, s.CollectedAt); e != nil {
			return out, e
		}
		if e = tx.QueryRow(ctx, `WITH r AS (UPDATE cmdb.platform_objects SET removed_at=$3 WHERE tenant_id=$1 AND instance_id=$2 AND removed_at IS NULL AND missing_snapshots>=$4 RETURNING 1) SELECT count(*) FROM r`,
			s.Tenant, out.InstanceID, s.CollectedAt, PlatformMissingLimit).Scan(&out.Removed); e != nil {
			return out, e
		}
	}
	e = tx.QueryRow(ctx, `SELECT count(*) FROM cmdb.platform_objects WHERE tenant_id=$1 AND instance_id=$2 AND last_seen=$3 AND asset_uid IS NOT NULL`, s.Tenant, out.InstanceID, s.CollectedAt).Scan(&out.Matched)
	return out, e
}

type PlatformInstance struct {
	ID             string         `json:"instance_id"`
	Platform       string         `json:"platform"`
	Instance       string         `json:"instance"`
	Name           string         `json:"name"`
	LastSnapshotAt *time.Time     `json:"last_snapshot_at"`
	LastCompleteAt *time.Time     `json:"last_complete_at"`
	Objects        map[string]int `json:"objects"`
	Matched        int            `json:"matched"`
	Unmatched      int            `json:"unmatched"`
	Removed        int            `json:"removed"`
	Errors         []string       `json:"errors"`
}

// PlatformInstances — экземпляры платформ организации с числом объектов по видам.
func (Store) PlatformInstances(ctx context.Context, tx pgx.Tx, tenant string) ([]PlatformInstance, error) {
	rows, e := tx.Query(ctx, `SELECT p.instance_id::text,p.platform,p.instance_key,p.name,p.last_snapshot_at,p.last_complete_at,p.errors,
 COALESCE((SELECT jsonb_object_agg(k.kind,k.n) FROM (SELECT o.kind,count(*) n FROM cmdb.platform_objects o WHERE o.tenant_id=p.tenant_id AND o.instance_id=p.instance_id AND o.removed_at IS NULL GROUP BY o.kind) k),'{}'::jsonb),
 (SELECT count(*) FROM cmdb.platform_objects o WHERE o.tenant_id=p.tenant_id AND o.instance_id=p.instance_id AND o.removed_at IS NULL AND o.asset_uid IS NOT NULL),
 (SELECT count(*) FROM cmdb.platform_objects o WHERE o.tenant_id=p.tenant_id AND o.instance_id=p.instance_id AND o.removed_at IS NULL AND o.asset_uid IS NULL AND o.kind IN ('host','vm','computer','chassis')),
 (SELECT count(*) FROM cmdb.platform_objects o WHERE o.tenant_id=p.tenant_id AND o.instance_id=p.instance_id AND o.removed_at IS NOT NULL)
FROM cmdb.platform_instances p WHERE p.tenant_id=$1 ORDER BY p.platform,p.name,p.instance_key`, tenant)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []PlatformInstance{}
	for rows.Next() {
		var p PlatformInstance
		var errs, objs []byte
		if e = rows.Scan(&p.ID, &p.Platform, &p.Instance, &p.Name, &p.LastSnapshotAt, &p.LastCompleteAt, &errs, &objs, &p.Matched, &p.Unmatched, &p.Removed); e != nil {
			return nil, e
		}
		p.Errors, p.Objects = []string{}, map[string]int{}
		_ = json.Unmarshal(errs, &p.Errors)
		_ = json.Unmarshal(objs, &p.Objects)
		out = append(out, p)
	}
	return out, rows.Err()
}

type PlatformObjectView struct {
	InstanceID   string         `json:"instance_id"`
	Platform     string         `json:"platform"`
	InstanceName string         `json:"instance_name"`
	Ref          string         `json:"ref"`
	Kind         string         `json:"kind"`
	Name         string         `json:"name"`
	AssetUID     *string        `json:"asset_uid"`
	Attrs        map[string]any `json:"attrs"`
	FirstSeen    time.Time      `json:"first_seen"`
	LastSeen     time.Time      `json:"last_seen"`
	RemovedAt    *time.Time     `json:"removed_at"`
}

func scanObject(r pgx.Row) (PlatformObjectView, error) {
	var o PlatformObjectView
	var attrs []byte
	e := r.Scan(&o.InstanceID, &o.Platform, &o.InstanceName, &o.Ref, &o.Kind, &o.Name, &o.AssetUID, &attrs, &o.FirstSeen, &o.LastSeen, &o.RemovedAt)
	if e == nil {
		o.Attrs = map[string]any{}
		_ = json.Unmarshal(attrs, &o.Attrs)
	}
	return o, e
}

// PlatformObjects — объекты экземпляра (фильтр по виду и имени; «не сопоставлены» — объекты-хосты без актива).
func (Store) PlatformObjects(ctx context.Context, tx pgx.Tx, tenant, instance, kind, query string, unmatched bool, offset, limit int) ([]PlatformObjectView, int, error) {
	if !identifier.Valid(instance) || (kind != "" && !platformObjKinds[kind]) || offset < 0 {
		return nil, 0, domain.Invalid
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var total int
	if e := tx.QueryRow(ctx, `SELECT count(*) FROM cmdb.platform_objects o WHERE o.tenant_id=$1 AND o.instance_id=$2 AND ($3='' OR o.kind=$3)
AND ($4='' OR lower(o.name) LIKE '%'||lower($4)||'%') AND (NOT $5 OR (o.asset_uid IS NULL AND o.kind IN ('host','vm','computer','chassis') AND o.removed_at IS NULL))`,
		tenant, instance, kind, query, unmatched).Scan(&total); e != nil {
		return nil, 0, e
	}
	rows, e := tx.Query(ctx, `SELECT o.instance_id::text,p.platform,COALESCE(NULLIF(p.name,''),p.instance_key),o.ref,o.kind,o.name,o.asset_uid::text,o.attrs,o.first_seen,o.last_seen,o.removed_at
FROM cmdb.platform_objects o JOIN cmdb.platform_instances p ON p.tenant_id=o.tenant_id AND p.instance_id=o.instance_id
WHERE o.tenant_id=$1 AND o.instance_id=$2 AND ($3='' OR o.kind=$3) AND ($4='' OR lower(o.name) LIKE '%'||lower($4)||'%')
AND (NOT $5 OR (o.asset_uid IS NULL AND o.kind IN ('host','vm','computer','chassis') AND o.removed_at IS NULL))
ORDER BY o.removed_at IS NOT NULL,o.kind,o.name,o.ref OFFSET $6 LIMIT $7`, tenant, instance, kind, query, unmatched, offset, limit)
	if e != nil {
		return nil, 0, e
	}
	defer rows.Close()
	out := []PlatformObjectView{}
	for rows.Next() {
		o, e := scanObject(rows)
		if e != nil {
			return nil, 0, e
		}
		out = append(out, o)
	}
	return out, total, rows.Err()
}

type PlatformLink struct {
	Type      string             `json:"type"`
	Direction string             `json:"direction"`
	Object    PlatformObjectView `json:"object"`
}

type AssetPlatformItem struct {
	Object PlatformObjectView `json:"object"`
	Links  []PlatformLink     `json:"links"`
}

// AssetPlatform — объекты платформ, сопоставленные с активом, и их связи (ВМ → хост → кластер и т. п.).
func (Store) AssetPlatform(ctx context.Context, tx pgx.Tx, tenant, asset string) ([]AssetPlatformItem, error) {
	if !identifier.Valid(asset) {
		return nil, domain.Invalid
	}
	rows, e := tx.Query(ctx, `SELECT o.instance_id::text,p.platform,COALESCE(NULLIF(p.name,''),p.instance_key),o.ref,o.kind,o.name,o.asset_uid::text,o.attrs,o.first_seen,o.last_seen,o.removed_at
FROM cmdb.platform_objects o JOIN cmdb.platform_instances p ON p.tenant_id=o.tenant_id AND p.instance_id=o.instance_id
WHERE o.tenant_id=$1 AND o.asset_uid=$2 ORDER BY o.removed_at IS NOT NULL,o.last_seen DESC LIMIT 20`, tenant, asset)
	if e != nil {
		return nil, e
	}
	items := []AssetPlatformItem{}
	for rows.Next() {
		o, e := scanObject(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		items = append(items, AssetPlatformItem{Object: o, Links: []PlatformLink{}})
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return nil, e
	}
	for i := range items {
		o := items[i].Object
		rows, e := tx.Query(ctx, `SELECT r.rel_type,CASE WHEN r.from_ref=$3 THEN 'out' ELSE 'in' END,
 t.instance_id::text,p.platform,COALESCE(NULLIF(p.name,''),p.instance_key),t.ref,t.kind,t.name,t.asset_uid::text,t.attrs,t.first_seen,t.last_seen,t.removed_at
FROM cmdb.platform_relations r JOIN cmdb.platform_objects t ON t.tenant_id=r.tenant_id AND t.instance_id=r.instance_id AND t.ref=CASE WHEN r.from_ref=$3 THEN r.to_ref ELSE r.from_ref END
JOIN cmdb.platform_instances p ON p.tenant_id=t.tenant_id AND p.instance_id=t.instance_id
WHERE r.tenant_id=$1 AND r.instance_id=$2 AND (r.from_ref=$3 OR r.to_ref=$3) ORDER BY 1,2,t.kind,t.name LIMIT 200`, tenant, o.InstanceID, o.Ref)
		if e != nil {
			return nil, e
		}
		for rows.Next() {
			var l PlatformLink
			var attrs []byte
			if e = rows.Scan(&l.Type, &l.Direction, &l.Object.InstanceID, &l.Object.Platform, &l.Object.InstanceName, &l.Object.Ref, &l.Object.Kind, &l.Object.Name, &l.Object.AssetUID, &attrs, &l.Object.FirstSeen, &l.Object.LastSeen, &l.Object.RemovedAt); e != nil {
				rows.Close()
				return nil, e
			}
			l.Object.Attrs = map[string]any{}
			_ = json.Unmarshal(attrs, &l.Object.Attrs)
			items[i].Links = append(items[i].Links, l)
		}
		rows.Close()
		if e = rows.Err(); e != nil {
			return nil, e
		}
	}
	return items, nil
}
