package sources

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// PortableDiscoveryHost — узел обследования portable-аудита (C23.04).
type PortableDiscoveryHost struct {
	IP            string    `json:"ip"`
	Kind          string    `json:"kind"`
	Ports         []int32   `json:"ports"`
	Outcome       string    `json:"outcome"`
	Reason        *string   `json:"reason"`
	Profile       *string   `json:"profile"`
	ObservationID *string   `json:"observation_id"`
	AssetUID      *string   `json:"asset_uid"`
	SeenAt        time.Time `json:"seen_at"`
}

// SavePortableDiscovery записывает узлы пакета: по каждому IP действует более поздний манифест; повтор того же
// пакета ничего не меняет.
func (Store) SavePortableDiscovery(ctx context.Context, tx pgx.Tx, tenant, source, packageSHA string, seen time.Time, hosts []PortableDiscoveryHost) (int64, error) {
	var changed int64
	for _, h := range hosts {
		tag, e := tx.Exec(ctx, `INSERT INTO sources.portable_discovery_hosts(tenant_id,source_id,ip,kind,ports,outcome,reason,profile,observation_id,package_sha256,seen_at)
VALUES($1,$2,$3::inet,$4,$5,$6,$7,$8,$9::uuid,$10,$11)
ON CONFLICT (tenant_id,source_id,ip) DO UPDATE SET kind=EXCLUDED.kind,ports=EXCLUDED.ports,outcome=EXCLUDED.outcome,reason=EXCLUDED.reason,profile=EXCLUDED.profile,
observation_id=EXCLUDED.observation_id,package_sha256=EXCLUDED.package_sha256,seen_at=EXCLUDED.seen_at
WHERE sources.portable_discovery_hosts.seen_at < EXCLUDED.seen_at`, tenant, source, h.IP, h.Kind, h.Ports, h.Outcome, h.Reason, h.Profile, h.ObservationID, packageSHA, seen.UTC())
		if e != nil {
			return changed, e
		}
		changed += tag.RowsAffected()
	}
	return changed, nil
}

// PortableDiscovery — узлы источника (необязательный фильтр исхода), по IP, до 5000; asset_uid — по наблюдению
// этого же пакета, если оно применено к активу.
func (Store) PortableDiscovery(ctx context.Context, tx pgx.Tx, tenant, source, outcome string) ([]PortableDiscoveryHost, error) {
	rows, e := tx.Query(ctx, `SELECT host(h.ip),h.kind,h.ports,h.outcome,h.reason,h.profile,h.observation_id::text,
(SELECT r.asset_uid::text FROM inventory.observation_results r WHERE r.tenant_id=h.tenant_id AND r.observation_id=h.observation_id),h.seen_at
FROM sources.portable_discovery_hosts h WHERE h.tenant_id=$1 AND h.source_id=$2 AND ($3='' OR h.outcome=$3) ORDER BY h.ip LIMIT 5000`, tenant, source, outcome)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []PortableDiscoveryHost{}
	for rows.Next() {
		var h PortableDiscoveryHost
		if e = rows.Scan(&h.IP, &h.Kind, &h.Ports, &h.Outcome, &h.Reason, &h.Profile, &h.ObservationID, &h.AssetUID, &h.SeenAt); e != nil {
			return nil, e
		}
		h.SeenAt = h.SeenAt.UTC()
		out = append(out, h)
	}
	return out, rows.Err()
}
