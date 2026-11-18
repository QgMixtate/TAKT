package app

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/portable"
	"github.com/jackc/pgx/v5"
)

// portableImportTimeout — предел на загрузку и импорт одного пакета через API. Общие таймауты сервера
// (10 с) и контекст авторизации (5 с) рассчитаны на короткие запросы, поэтому здесь продлеваются явно.
const portableImportTimeout = 5 * time.Minute

// portableImportBudget — от начала запроса (включая приём тела); после него новые записи пакета не начинаются, ответ уходит с complete=false.
// Меньше portableImportTimeout и proxy_read_timeout 300 с в deploy/nginx.conf с запасом на запись в обработке.
const portableImportBudget = 4 * time.Minute

// portableImportHandler — HTTPS-путь C23.03: POST /api/v1/sources/{source_id}/portable-import, тело —
// portable-пакет (application/zip). Права sources:admin; tenant — только из учётных данных. Проверки те же,
// что у консольного portable-import (подписи, лимиты, карантин); повтор того же пакета идемпотентен, поэтому
// оборванную загрузку продолжают повторной отправкой.
func (r *Registry) portableImportHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.RawQuery != "" {
			access.APIError(w, 400, "INVALID_QUERY")
			return
		}
		if r.Machine == nil || r.Machine.Sources == nil || !r.Inventory12Enabled() {
			access.APIError(w, 501, "CAPABILITY_NOT_ENABLED")
			return
		}
		source := req.PathValue("source_id")
		if !identifier.Valid(source) {
			access.APIError(w, 404, "NOT_FOUND")
			return
		}
		if ct := req.Header.Get("Content-Type"); ct != "application/zip" && ct != "application/octet-stream" {
			access.APIError(w, 415, "UNSUPPORTED_MEDIA_TYPE")
			return
		}
		id, _ := access.Identity(req.Context())
		deadline := time.Now().Add(portableImportTimeout)
		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(deadline)
		_ = rc.SetWriteDeadline(deadline)
		ctx, cancel := context.WithDeadline(context.WithoutCancel(req.Context()), deadline)
		defer cancel()
		limit := portable.DefaultLimits().MaxPackageBytes
		data, e := io.ReadAll(http.MaxBytesReader(w, req.Body, limit))
		if e != nil {
			var tooBig *http.MaxBytesError
			if errors.As(e, &tooBig) {
				access.APIError(w, 413, "PAYLOAD_TOO_LARGE")
				return
			}
			access.APIError(w, 400, "INVALID_BODY")
			return
		}
		report, e := r.ImportPortableUntil(ctx, r.Machine.Sources, id.TenantID, source, data, deadline.Add(portableImportBudget-portableImportTimeout))
		if e != nil {
			switch {
			case errors.Is(e, domain.NotFound) || errors.Is(e, domain.Unauthorized):
				// чужой tenant, неизвестный или неактивный источник — не раскрывать различие
				access.APIError(w, 404, "NOT_FOUND")
			case errors.Is(e, portable.ErrLimits):
				access.APIError(w, 413, "PAYLOAD_TOO_LARGE")
			case errors.Is(e, ErrPortableEncryptionKey) || errors.Is(e, ErrSecretsUnavailable) || errors.Is(e, portable.ErrEncryptedKey):
				access.APIError(w, 422, "PACKAGE_ENCRYPTION_KEY_UNKNOWN") // пакет зашифрован не ключом этой организации
			case errors.Is(e, portable.ErrEnvelope):
				access.APIError(w, 422, "PACKAGE_REJECTED")
			case errors.Is(e, domain.Invalid) || isPortableRejection(e):
				access.APIError(w, 422, "PACKAGE_REJECTED")
			default:
				registryError(w, e)
			}
			return
		}
		if e = r.Machine.Sources.AuditPortableImport(ctx, id.TenantID, id.UserID, source); e != nil {
			registryError(w, e)
			return
		}
		registryJSON(w, report)
	})
}

// isPortableRejection — пакет целиком не прошёл проверку формата или подписи (ничего не применено).
func isPortableRejection(e error) bool {
	return errors.Is(e, portable.ErrFormat) || errors.Is(e, portable.ErrSignature)
}

// C23 (стенд, вопрос пользователя о portable): регистрация portable-источника из Web. Площадки и сегменты — для
// команды init; регистрация — вставкой вывода init (ключ подписи остаётся на ПК, центр получает только открытый).
type portableRegistrationBody struct {
	Site       string `json:"site_id"`
	Scope      string `json:"scope_id"`
	Source     string `json:"source_id"`
	Generation string `json:"generation_id"`
	PublicKey  string `json:"public_key"`
}

type PortableRegistered struct {
	Source string `json:"source_id"`
	KeyID  string `json:"key_id"`
}

func (r *Registry) portableScopesHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.RawQuery != "" {
			access.APIError(w, 400, "INVALID_QUERY")
			return
		}
		r.discoveryDo(w, req, http.StatusOK, "sources:admin", func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
			items, e := (sources.Store{}).PortableScopes(ctx, tx, id.TenantID)
			if e != nil {
				return nil, e
			}
			// ключ шифрования пакетов (если включён) — Web подставляет его в команду init
			enc, e := r.PortableEncryptionKey(ctx, id.TenantID, false)
			if errors.Is(e, ErrSecretsUnavailable) {
				enc, e = nil, nil
			}
			return map[string]any{"tenant_id": id.TenantID, "items": items, "encryption": enc, "encryption_available": r.Secrets != nil}, e
		})
	})
}

func (r *Registry) portableRegisterHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body portableRegistrationBody
		if !readOperationBody(w, req, &body) {
			return
		}
		if r.Machine == nil || r.Machine.Sources == nil { // регистрации протокол 1.2 не нужен (он нужен импорту)
			access.APIError(w, 501, "CAPABILITY_NOT_ENABLED")
			return
		}
		pub, err := base64.RawURLEncoding.Strict().DecodeString(body.PublicKey)
		if err != nil {
			access.APIError(w, 422, "INVALID_INPUT")
			return
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		keyID, e := r.Machine.Sources.RegisterPortable(ctx, "user:"+id.UserID, sources.PortableRegistration{Tenant: id.TenantID, Site: body.Site, Scope: body.Scope, Source: body.Source, Generation: body.Generation, PublicKey: pub})
		if e != nil {
			cmdbError(w, req, e)
			return
		}
		registryJSONStatus(w, http.StatusCreated, PortableRegistered{Source: body.Source, KeyID: keyID})
	})
}

// portableEncryptionHandler включает шифрование portable-пакетов организации: создаёт ключ (повтор возвращает тот же).
func (r *Registry) portableEncryptionHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body struct{}
		if !readOperationBody(w, req, &body) {
			return
		}
		if r.Secrets == nil || r.Machine == nil || r.Machine.Sources == nil {
			access.APIError(w, 501, "CAPABILITY_NOT_ENABLED")
			return
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		enc, e := r.PortableEncryptionKey(ctx, id.TenantID, true)
		if e != nil {
			registryError(w, e)
			return
		}
		if e = r.Machine.Sources.AuditPortableAction(ctx, id.TenantID, "user:"+id.UserID, "source.portable_encryption_enabled", enc.KeyID); e != nil {
			registryError(w, e)
			return
		}
		registryJSON(w, enc)
	})
}

// portableDiscoveryHandler — GET /api/v1/sources/{source_id}/portable-discovery[?outcome=…]: найденные узлы
// portable-аудита (C23.04); чтение — sources:read.
func (r *Registry) portableDiscoveryHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		source := req.PathValue("source_id")
		outcome := req.URL.Query().Get("outcome")
		allowed := map[string]bool{"": true, "collected": true, "no_profile": true, "no_access": true, "unreachable": true, "skipped": true}
		if !identifier.Valid(source) || !allowed[outcome] || len(req.URL.Query()) > 1 {
			access.APIError(w, 400, "INVALID_QUERY")
			return
		}
		r.discoveryDo(w, req, http.StatusOK, "sources:read", func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
			hosts, e := src51.PortableDiscovery(ctx, tx, id.TenantID, source, outcome)
			return map[string]any{"hosts": hosts}, e
		})
	})
}
