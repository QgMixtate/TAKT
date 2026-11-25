package sources

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// PortableRegistration — регистрация portable-источника по открытому ключу из `surveyscan-portable init` (C23.03).
// У portable-источника нет mTLS-личности и сети во время аудита: доверие задаёт оператор центра, указывая ключ.
type PortableRegistration struct {
	Tenant, Site, Scope, Source, Generation string
	PublicKey                               []byte
}

// PortableKeyID — key_id привязки: первые 16 байт SHA-256 открытого ключа в форме UUID (так же считает portable-пакет).
func PortableKeyID(pub []byte) string {
	sum := sha256.Sum256(pub)
	h := hex.EncodeToString(sum[:16])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// RegisterPortable создаёт активный источник вида portable и привязку его ключа (namespace host, scope площадки).
// Повтор с теми же данными идемпотентен; другой вид/поколение/ключ для того же source_id — конфликт.
func (s *MachineService) RegisterPortable(ctx context.Context, actorRef string, r PortableRegistration) (string, error) {
	if !identifier.Valid(r.Tenant) || !identifier.Valid(r.Site) || !identifier.Valid(r.Scope) || !identifier.Valid(r.Source) || !identifier.Valid(r.Generation) || len(r.PublicKey) != 32 {
		return "", domain.Invalid
	}
	keyID := PortableKeyID(r.PublicKey)
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return "", e
	}
	defer tx.Rollback(ctx)
	var ok bool
	if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM scope.network_scopes WHERE tenant_id=$1 AND site_id=$2 AND scope_id=$3)", r.Tenant, r.Site, r.Scope).Scan(&ok); e != nil {
		return "", e
	}
	if !ok {
		return "", domain.NotFound
	}
	var kind, generation, state string
	e = tx.QueryRow(ctx, "SELECT source_kind,generation_id::text,state FROM sources.sources WHERE tenant_id=$1 AND source_id=$2 FOR UPDATE", r.Tenant, r.Source).Scan(&kind, &generation, &state)
	switch {
	case errors.Is(e, pgx.ErrNoRows):
		if _, e = tx.Exec(ctx, "INSERT INTO sources.sources(tenant_id,source_id,source_kind,site_id,state,generation_id) VALUES($1,$2,'portable',$3,'active',$4)", r.Tenant, r.Source, r.Site, r.Generation); e != nil {
			return "", e
		}
	case e != nil:
		return "", e
	case kind != "portable" || generation != r.Generation || state != "active":
		return "", domain.Conflict
	}
	// у источника — один ключ: другой ключ для того же source_id/поколения — конфликт (раньше добавлялась вторая
	// привязка; найдено тестом регистрации из Web). Смена ключа — новый portable-источник.
	var otherKey bool
	if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM sources.ingest_bindings WHERE tenant_id=$1 AND source_id=$2 AND generation_id=$3 AND key_id<>$4)", r.Tenant, r.Source, r.Generation, keyID).Scan(&otherKey); e != nil {
		return "", e
	}
	if otherKey {
		return "", domain.Conflict
	}
	var existing []byte
	e = tx.QueryRow(ctx, "SELECT public_key FROM sources.ingest_bindings WHERE tenant_id=$1 AND source_id=$2 AND generation_id=$3 AND key_id=$4 AND namespace='host' AND scope_id=$5", r.Tenant, r.Source, r.Generation, keyID, r.Scope).Scan(&existing)
	switch {
	case errors.Is(e, pgx.ErrNoRows):
		if _, e = tx.Exec(ctx, "INSERT INTO sources.ingest_bindings(tenant_id,source_id,generation_id,key_id,namespace,scope_id,public_key) VALUES($1,$2,$3,$4,'host',$5,$6)", r.Tenant, r.Source, r.Generation, keyID, r.Scope, r.PublicKey); e != nil {
			return "", e
		}
	case e != nil:
		return "", e
	case string(existing) != string(r.PublicKey):
		return "", domain.Conflict
	}
	if e = s.Audit.Record(ctx, tx, r.Tenant, actorRef, "source.portable_registered", "source", r.Source); e != nil {
		return "", e
	}
	return keyID, tx.Commit(ctx)
}

// PortableTrust возвращает key_id и открытый ключ активной привязки активного portable-источника.
func (s *MachineService) PortableTrust(ctx context.Context, tenant, source string) (string, []byte, error) {
	if !identifier.Valid(tenant) || !identifier.Valid(source) {
		return "", nil, domain.Invalid
	}
	var keyID string
	var pub []byte
	e := s.Pool.QueryRow(ctx, `SELECT b.key_id::text,b.public_key FROM sources.ingest_bindings b JOIN sources.sources s USING(tenant_id,source_id)
WHERE b.tenant_id=$1 AND b.source_id=$2 AND s.source_kind='portable' AND s.state='active' AND b.active AND b.generation_id=s.generation_id LIMIT 1`, tenant, source).Scan(&keyID, &pub)
	if errors.Is(e, pgx.ErrNoRows) {
		return "", nil, domain.NotFound
	}
	return keyID, pub, e
}

// AuditPortableImport фиксирует загрузку portable-пакета пользователем через API (кто, какой источник).
func (s *MachineService) AuditPortableImport(ctx context.Context, tenant, actorRef, source string) error {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if e = s.Audit.Record(ctx, tx, tenant, actorRef, "source.portable_imported", "source", source); e != nil {
		return e
	}
	// загрузка пакета — единственный «контакт» носителя: время последней загрузки видно в Web (ISSUES №69)
	if _, e = tx.Exec(ctx, `UPDATE sources.sources SET last_contact_at=GREATEST(COALESCE(last_contact_at,'-infinity'::timestamptz),clock_timestamp()) WHERE tenant_id=$1 AND source_id=$2 AND source_kind='portable'`, tenant, source); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

// AuditPortableAction — запись аудита действия с portable-аудитом организации (например, включение шифрования).
func (s *MachineService) AuditPortableAction(ctx context.Context, tenant, actorRef, action, object string) error {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if e = s.Audit.Record(ctx, tx, tenant, actorRef, action, "portable_encryption", object); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

// PortableScope — площадка и сегмент для команды init portable-аудита (Web подставляет их в команду).
type PortableScope struct {
	Site      string `json:"site_id"`
	SiteName  string `json:"site_name"`
	Scope     string `json:"scope_id"`
	Namespace string `json:"namespace"`
}

func (Store) PortableScopes(ctx context.Context, tx pgx.Tx, tenant string) ([]PortableScope, error) {
	rows, e := tx.Query(ctx, `SELECT n.site_id::text,s.name,n.scope_id::text,n.namespace FROM scope.network_scopes n JOIN scope.sites s ON s.tenant_id=n.tenant_id AND s.site_id=n.site_id
WHERE n.tenant_id=$1 ORDER BY s.name,n.namespace LIMIT 200`, tenant)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []PortableScope{}
	for rows.Next() {
		var p PortableScope
		if e = rows.Scan(&p.Site, &p.SiteName, &p.Scope, &p.Namespace); e != nil {
			return nil, e
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
