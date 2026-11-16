package sources

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	access "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// Коды регистрации (C52.01; decisions/C52-rust-agents-and-installers.md): установка «скачал → ввёл код». Код —
// 100 бит случайности в виде SSR-XXXXX-XXXXX-XXXXX-XXXXX (Crockford base32), в центре — только SHA-256. Надстройка над
// выдачей grant (C03 не меняется): по коду центр создаёт источник и grant под CSR, подготовленный машиной (`prepare`),
// дальше — обычный `enroll`.

type RegistrationCode struct {
	ID          string     `json:"code_id"`
	Kind        string     `json:"source_kind"`
	Site        string     `json:"site_id"`
	Collector   *string    `json:"collector_id"`
	Platform    *string    `json:"inventory_platform"`
	MaxUses     int        `json:"max_uses"`
	Used        int        `json:"used"`
	ExpiresAt   time.Time  `json:"expires_at"`
	RevokedAt   *time.Time `json:"revoked_at"`
	Comment     string     `json:"comment"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	State       string     `json:"state"` // active | exhausted | expired | revoked
	Code        string     `json:"code,omitempty"`
	Fingerprint string     `json:"center_fingerprint,omitempty"`
}

type RegistrationCodeInput struct {
	Kind      string `json:"source_kind"`
	Site      string `json:"site_id"`
	Collector string `json:"collector_source_id,omitempty"` // источник collector площадки (для агента)
	Platform  string `json:"inventory_platform,omitempty"`
	MaxUses   int    `json:"max_uses"`
	TTLHours  int    `json:"ttl_hours"`
	Comment   string `json:"comment"`
}

// RegistrationRequest — запрос устанавливаемой машины: код и подготовленные `prepare` идентификатор, хеш CSR и ключ.
type RegistrationRequest struct {
	Code        string `json:"registration_code"`
	SourceID    string `json:"source_id"`
	CSRHash     string `json:"csr_sha256"`
	PublicKey   string `json:"signing_public_key"`
	Hostname    string `json:"hostname"`
	Platform    string `json:"inventory_platform,omitempty"`
	Acquisition string `json:"acquisition,omitempty"`
}

// RegistrationResult — grant для обычного enroll и сведения для конфигурации устанавливаемой машины.
type RegistrationResult struct {
	Grant           contracts.EnrollmentGrant `json:"grant"`
	Tenant          string                    `json:"tenant_id"`
	Site            string                    `json:"site_id"`
	Scope           string                    `json:"network_scope_id"`
	CollectorSource *string                   `json:"collector_source_id"`
}

// ErrRegistrationCode — код неизвестен, просрочен, отозван или исчерпан (причина наружу не раскрывается).
var ErrRegistrationCode = fmt.Errorf("sources: registration code not usable: %w", domain.Unauthorized)

// ErrAlreadyRegistered — этот CSR уже зарегистрирован этим кодом: машина должна использовать полученный ранее grant.
var ErrAlreadyRegistered = fmt.Errorf("sources: csr already registered with this code: %w", domain.Conflict)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var codeShape = regexp.MustCompile(`^SSR-[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){3}$`)
var hostShape = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)

func newRegistrationCode() string {
	b := make([]byte, 20)
	if _, e := rand.Read(b); e != nil {
		panic("secure randomness unavailable")
	}
	var sb strings.Builder
	sb.WriteString("SSR")
	for i, x := range b {
		if i%5 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(crockford[x&31])
	}
	return sb.String()
}

// NormalizeCode — ввод человека: регистр, пробелы, I/L→1, O→0 (Crockford).
func NormalizeCode(code string) string {
	r := strings.NewReplacer(" ", "", "I", "1", "L", "1", "O", "0").Replace(strings.ToUpper(strings.TrimSpace(code)))
	if !strings.HasPrefix(r, "SSR") {
		return ""
	}
	body := strings.ReplaceAll(strings.TrimPrefix(r, "SSR"), "-", "")
	if len(body) != 20 {
		return ""
	}
	out := "SSR"
	for i := 0; i < 20; i += 5 {
		out += "-" + body[i:i+5]
	}
	if !codeShape.MatchString(out) {
		return ""
	}
	return out
}

func codeHash(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

func scanCode(r pgx.Row, c *RegistrationCode) error {
	return r.Scan(&c.ID, &c.Kind, &c.Site, &c.Collector, &c.Platform, &c.MaxUses, &c.Used, &c.ExpiresAt, &c.RevokedAt, &c.Comment, &c.CreatedBy, &c.CreatedAt, &c.State)
}

// CreateCode — администратор (sources:admin) заводит код; открытый код возвращается один раз.
func (s *MachineService) CreateCode(ctx context.Context, tx pgx.Tx, actor access.Identity, in RegistrationCodeInput) (RegistrationCode, error) {
	if _, e := s.Auth.Authorize(ctx, tx, actor.CredentialID, actor.TenantID, "sources:admin"); e != nil {
		return RegistrationCode{}, e
	}
	comment := strings.TrimSpace(in.Comment)
	if (in.Kind != "agent" && in.Kind != "collector") || !identifier.Valid(in.Site) || in.MaxUses < 1 || in.MaxUses > 10000 ||
		in.TTLHours < 1 || in.TTLHours > 24*30 || utf8.RuneCountInString(comment) > 256 || (in.Kind == "agent") != (in.Collector != "") {
		return RegistrationCode{}, domain.Invalid
	}
	var platform *string
	if in.Platform != "" {
		if in.Kind != "agent" || (in.Platform != contracts.InventoryPlatform12 && in.Platform != contracts.InventoryPlatformLinux12) {
			return RegistrationCode{}, domain.Invalid
		}
		platform = &in.Platform
	}
	var collector *string
	var ok bool
	if in.Kind == "agent" {
		if !identifier.Valid(in.Collector) {
			return RegistrationCode{}, domain.Invalid
		}
		var id string
		e := tx.QueryRow(ctx, `SELECT c.collector_id::text FROM sources.collectors c JOIN sources.sources s USING(tenant_id,source_id)
WHERE c.tenant_id=$1 AND c.source_id=$2 AND s.site_id=$3 AND s.state='active'`, actor.TenantID, in.Collector, in.Site).Scan(&id)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return RegistrationCode{}, e
		}
		ok, collector = e == nil, &id
	} else if e := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM scope.sites WHERE tenant_id=$1 AND site_id=$2)", actor.TenantID, in.Site).Scan(&ok); e != nil {
		return RegistrationCode{}, e
	}
	if !ok {
		return RegistrationCode{}, domain.Invalid // площадка или активный collector этой площадки не найдены
	}
	code, id := newRegistrationCode(), identifier.New()
	if _, e := tx.Exec(ctx, `INSERT INTO sources.registration_codes(tenant_id,code_id,code_hash,source_kind,site_id,collector_id,inventory_platform,max_uses,expires_at,comment,created_by)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,clock_timestamp()+make_interval(hours=>$9),$10,$11)`, actor.TenantID, id, codeHash(code), in.Kind, in.Site, collector, platform, in.MaxUses, in.TTLHours, comment, "user:"+actor.UserID); e != nil {
		return RegistrationCode{}, e
	}
	if e := s.Audit.Record(ctx, tx, actor.TenantID, actor.UserID, "source.registration_code_created", "registration_code", id); e != nil {
		return RegistrationCode{}, e
	}
	out, e := s.code(ctx, tx, actor.TenantID, id)
	out.Code = code
	return out, e
}

func (s *MachineService) code(ctx context.Context, tx pgx.Tx, tenant, id string) (RegistrationCode, error) {
	var c RegistrationCode
	e := scanCode(tx.QueryRow(ctx, "SELECT code_id::text,source_kind,site_id::text,collector_id::text,inventory_platform,max_uses,used,expires_at,revoked_at,comment,created_by,created_at,CASE WHEN revoked_at IS NOT NULL THEN 'revoked' WHEN used>=max_uses THEN 'exhausted' WHEN expires_at<=clock_timestamp() THEN 'expired' ELSE 'active' END FROM sources.registration_codes WHERE tenant_id=$1 AND code_id=$2", tenant, id), &c)
	if errors.Is(e, pgx.ErrNoRows) {
		return c, domain.NotFound
	}
	return c, e
}

// Codes — коды организации (новые сверху).
func (s *MachineService) Codes(ctx context.Context, tx pgx.Tx, actor access.Identity) ([]RegistrationCode, error) {
	if _, e := s.Auth.Authorize(ctx, tx, actor.CredentialID, actor.TenantID, "sources:admin"); e != nil {
		return nil, e
	}
	rows, e := tx.Query(ctx, `SELECT code_id::text,source_kind,site_id::text,collector_id::text,inventory_platform,max_uses,used,expires_at,revoked_at,comment,created_by,created_at,
CASE WHEN revoked_at IS NOT NULL THEN 'revoked' WHEN used>=max_uses THEN 'exhausted' WHEN expires_at<=clock_timestamp() THEN 'expired' ELSE 'active' END
FROM sources.registration_codes WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 200`, actor.TenantID)
	if e != nil {
		return nil, e
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (RegistrationCode, error) {
		var c RegistrationCode
		return c, scanCode(r, &c)
	})
}

// RevokeCode — отзыв: дальнейшие установки по коду отклоняются; уже созданные источники не трогаются.
func (s *MachineService) RevokeCode(ctx context.Context, tx pgx.Tx, actor access.Identity, id string) (RegistrationCode, error) {
	if _, e := s.Auth.Authorize(ctx, tx, actor.CredentialID, actor.TenantID, "sources:admin"); e != nil {
		return RegistrationCode{}, e
	}
	if !identifier.Valid(id) {
		return RegistrationCode{}, domain.NotFound
	}
	tag, e := tx.Exec(ctx, "UPDATE sources.registration_codes SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND code_id=$2 AND revoked_at IS NULL", actor.TenantID, id)
	if e != nil {
		return RegistrationCode{}, e
	}
	if tag.RowsAffected() == 1 {
		if e = s.Audit.Record(ctx, tx, actor.TenantID, actor.UserID, "source.registration_code_revoked", "registration_code", id); e != nil {
			return RegistrationCode{}, e
		}
	}
	return s.code(ctx, tx, actor.TenantID, id)
}

// Register — установка по коду (без входа; ограничение частоты по адресу вызывающего и по коду): проверка кода,
// источник и grant под CSR машины в одной транзакции, счётчик установок. Повтор того же CSR — ErrAlreadyRegistered.
func (s *MachineService) Register(ctx context.Context, remote string, req RegistrationRequest) (RegistrationResult, error) {
	code := NormalizeCode(req.Code)
	public, e := base64.RawURLEncoding.Strict().DecodeString(req.PublicKey)
	if code == "" || !identifier.Valid(req.SourceID) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(req.CSRHash) || e != nil || len(public) != 32 || !hostShape.MatchString(req.Hostname) {
		return RegistrationResult{}, domain.Invalid
	}
	if e = s.rate(ctx, "register:"+remote, 120); e != nil {
		return RegistrationResult{}, e
	}
	if e = s.rate(ctx, "register-code:"+codeHash(code), 60); e != nil {
		return RegistrationResult{}, e
	}
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return RegistrationResult{}, e
	}
	defer tx.Rollback(ctx)
	var c RegistrationCode
	var tenant string
	var live, seen bool
	e = tx.QueryRow(ctx, `SELECT c.tenant_id::text,c.code_id::text,c.source_kind,c.site_id::text,c.collector_id::text,c.inventory_platform,c.max_uses,c.used,
c.revoked_at IS NULL AND c.expires_at>clock_timestamp(),EXISTS(SELECT 1 FROM sources.registration_uses u WHERE u.tenant_id=c.tenant_id AND u.code_id=c.code_id AND u.csr_sha256=$2)
FROM sources.registration_codes c WHERE c.code_hash=$1 FOR UPDATE OF c`, codeHash(code), req.CSRHash).
		Scan(&tenant, &c.ID, &c.Kind, &c.Site, &c.Collector, &c.Platform, &c.MaxUses, &c.Used, &live, &seen)
	if errors.Is(e, pgx.ErrNoRows) {
		return RegistrationResult{}, ErrRegistrationCode
	}
	if e != nil {
		return RegistrationResult{}, e
	}
	if seen {
		return RegistrationResult{}, ErrAlreadyRegistered
	}
	if !live || c.Used >= c.MaxUses {
		return RegistrationResult{}, ErrRegistrationCode
	}
	grant := contracts.EnrollmentGrantRequest{TenantID: tenant, SourceID: req.SourceID, Kind: c.Kind, SiteID: c.Site, CollectorID: c.Collector, TTL: 900, CSRHash: req.CSRHash, PublicKey: req.PublicKey}
	platform, acquisition := "", ""
	if c.Kind == "agent" {
		platform, acquisition = req.Platform, req.Acquisition
		if platform == "" {
			platform = contracts.InventoryPlatform12
		}
		if acquisition == "" {
			acquisition = "agent"
		}
		if (c.Platform != nil && *c.Platform != platform) || (platform != contracts.InventoryPlatform12 && platform != contracts.InventoryPlatformLinux12) || acquisition != "agent" {
			return RegistrationResult{}, domain.Invalid
		}
		grant.InventoryPlatform, grant.Acquisition = platform, acquisition
	} else if req.Platform != "" || req.Acquisition != "" {
		return RegistrationResult{}, domain.Invalid
	}
	g, e := s.grantTx(ctx, tx, grant, platform, acquisition, "registration:"+c.ID)
	if e != nil {
		return RegistrationResult{}, e
	}
	out := RegistrationResult{Grant: g, Tenant: tenant, Site: c.Site}
	if e = tx.QueryRow(ctx, `SELECT g.scope_id::text,(SELECT s.source_id::text FROM sources.collectors s WHERE s.tenant_id=g.tenant_id AND s.collector_id=g.collector_id AND $3='agent')
FROM sources.enrollment_grants g WHERE g.tenant_id=$1 AND g.grant_id=$2`, tenant, g.ID, c.Kind).Scan(&out.Scope, &out.CollectorSource); e != nil {
		return RegistrationResult{}, e
	}
	if _, e = tx.Exec(ctx, "UPDATE sources.registration_codes SET used=used+1 WHERE tenant_id=$1 AND code_id=$2", tenant, c.ID); e != nil {
		return out, e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO sources.registration_uses(tenant_id,code_id,source_id,csr_sha256,hostname) VALUES($1,$2,$3,$4,$5)", tenant, c.ID, req.SourceID, req.CSRHash, req.Hostname); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

// CodeUse — источник, созданный по коду (для списка в Web).
type CodeUse struct {
	Source       string    `json:"source_id"`
	Hostname     string    `json:"hostname"`
	RegisteredAt time.Time `json:"registered_at"`
}

// CodeUses — установки по коду.
func (s *MachineService) CodeUses(ctx context.Context, tx pgx.Tx, actor access.Identity, id string) ([]CodeUse, error) {
	if _, e := s.Auth.Authorize(ctx, tx, actor.CredentialID, actor.TenantID, "sources:admin"); e != nil {
		return nil, e
	}
	rows, e := tx.Query(ctx, "SELECT source_id::text,hostname,registered_at FROM sources.registration_uses WHERE tenant_id=$1 AND code_id::text=$2 ORDER BY registered_at", actor.TenantID, id)
	if e != nil {
		return nil, e
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (CodeUse, error) {
		var u CodeUse
		return u, r.Scan(&u.Source, &u.Hostname, &u.RegisteredAt)
	})
}
