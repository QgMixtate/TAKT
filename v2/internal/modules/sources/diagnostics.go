package sources

import (
	"context"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	access "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/jackc/pgx/v5"
	"time"
)

type DiagnosticSource struct {
	Source           string                        `json:"source_id"`
	Kind             string                        `json:"source_kind"`
	State            string                        `json:"state"`
	HeartbeatAge     *float64                      `json:"heartbeat_age_seconds"`
	InventoryAge     *float64                      `json:"inventory_age_seconds"`
	HeartbeatSeconds int                           `json:"heartbeat_seconds"`
	Desired          string                        `json:"desired_profile_revision"`
	Applied          *string                       `json:"applied_profile_revision"`
	IdentityExpires  *time.Time                    `json:"identity_expires_at"`
	Reported         *contracts.RuntimeDiagnostics `json:"reported_runtime"`
	ReportedAge      *float64                      `json:"runtime_report_age_seconds"`
	// Paused — источник цели сбора, все цели которого отключены (или их учётки выключены): предупреждения о
	// контакте не нужны (стенд, задание №12). В ответ не выводится (контракт диагностики не меняется).
	Paused bool `json:"-"`
}

func (s *MachineService) Diagnostics(ctx context.Context, actor access.Identity) ([]DiagnosticSource, error) {
	tx, e := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	if _, e = s.Auth.Authorize(ctx, tx, actor.CredentialID, actor.TenantID, "sources:read"); e != nil {
		return nil, e
	}
	rows, e := tx.Query(ctx, `SELECT s.source_id::text,s.source_kind,s.state,extract(epoch FROM clock_timestamp()-GREATEST(s.last_contact_at,h.last_contact_at))::float8,extract(epoch FROM clock_timestamp()-GREATEST(s.last_successful_inventory_at,ip.last_successful_inventory_at))::float8,COALESCE(p.heartbeat_seconds,60),COALESCE(p.revision::text,'1'),progress.applied_revision::text,(SELECT max(m.expires_at) FROM sources.machine_identities m WHERE m.tenant_id=s.tenant_id AND m.source_id=s.source_id AND m.generation_id=s.generation_id AND NOT m.revoked),d.collected_at,d.pending_files,d.pending_bytes,d.oldest_pending_at,d.disk_available_bytes,d.certificate_expires_at,extract(epoch FROM clock_timestamp()-d.received_at)::float8,
EXISTS(SELECT 1 FROM sources.remote_targets t WHERE t.tenant_id=s.tenant_id AND t.agent_source_id=s.source_id)
 AND NOT EXISTS(SELECT 1 FROM sources.remote_targets t JOIN sources.collect_credentials c ON c.tenant_id=t.tenant_id AND c.credential_id=t.credential_id
  WHERE t.tenant_id=s.tenant_id AND t.agent_source_id=s.source_id AND t.state<>'disabled' AND c.active)
FROM sources.sources s LEFT JOIN sources.heartbeat_state h USING(tenant_id,source_id,generation_id) LEFT JOIN sources.inventory_progress ip USING(tenant_id,source_id,generation_id) LEFT JOIN sources.profiles p USING(tenant_id,source_id) LEFT JOIN sources.profile_progress progress USING(tenant_id,source_id,generation_id) LEFT JOIN sources.runtime_diagnostics d USING(tenant_id,source_id,generation_id) WHERE s.tenant_id=$1 ORDER BY s.source_id LIMIT 1001`, actor.TenantID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []DiagnosticSource{}
	for rows.Next() {
		var item DiagnosticSource
		var collected, oldest, expires *time.Time
		var files *int
		var bytes, disk *int64
		if e = rows.Scan(&item.Source, &item.Kind, &item.State, &item.HeartbeatAge, &item.InventoryAge, &item.HeartbeatSeconds, &item.Desired, &item.Applied, &item.IdentityExpires, &collected, &files, &bytes, &oldest, &disk, &expires, &item.ReportedAge, &item.Paused); e != nil {
			return nil, e
		}
		if collected != nil && files != nil && bytes != nil && expires != nil {
			item.Reported = &contracts.RuntimeDiagnostics{Collected: *collected, PendingFiles: *files, PendingBytes: *bytes, OldestPending: oldest, DiskAvailable: disk, CertificateExpires: *expires}
		}
		out = append(out, item)
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	if e = tx.Commit(ctx); e != nil {
		return nil, e
	}
	return out, nil
}
