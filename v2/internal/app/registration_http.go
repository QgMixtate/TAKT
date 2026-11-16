package app

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
)

// Установка по коду (C52.01): Web — коды регистрации (администратор); машина — сертификат УЦ центра с отпечатком
// (установщик сверяет его с отпечатком, показанным вместе с кодом) и регистрация по коду → grant → обычный enroll.

// CenterFingerprint — SHA-256 сертификата УЦ центра (hex, 64 символа): его доверие получает агент/collector.
func CenterFingerprint(ca *x509.Certificate) string {
	sum := sha256.Sum256(ca.Raw)
	return hex.EncodeToString(sum[:])
}

func (r *Registry) registrationDo(w http.ResponseWriter, req *http.Request, status int, fn func(ctx context.Context, tx pgx.Tx, id accessport.Identity, m *sources.MachineService) (any, error)) {
	if r.Machine == nil || r.Machine.Sources == nil {
		access.APIError(w, 409, "CAPABILITY_NOT_ENABLED")
		return
	}
	ctx, cancel, id := cmdbContext(req)
	defer cancel()
	tx, e := r.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		registryError(w, e)
		return
	}
	defer tx.Rollback(ctx)
	out, e := fn(ctx, tx, id, r.Machine.Sources)
	if e == nil {
		e = tx.Commit(ctx)
	}
	if e != nil {
		cmdbError(w, req, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	registryJSONStatus(w, status, out)
}

func (r *Registry) registrationHandlers() map[string]http.Handler {
	h := map[string]http.Handler{}
	h["GET /api/v1/registration-codes"] = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		r.registrationDo(w, req, 200, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, m *sources.MachineService) (any, error) {
			items, e := m.Codes(ctx, tx, id)
			return map[string]any{"items": items, "center_fingerprint": r.Machine.Fingerprint}, e
		})
	})
	h["POST /api/v1/registration-codes"] = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body sources.RegistrationCodeInput
		if !readOperationBody(w, req, &body) {
			return
		}
		r.registrationDo(w, req, 201, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, m *sources.MachineService) (any, error) {
			c, e := m.CreateCode(ctx, tx, id, body)
			c.Fingerprint = r.Machine.Fingerprint
			return c, e
		})
	})
	h["POST /api/v1/registration-codes/{code_id}/revoke"] = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body struct{}
		if !readOperationBody(w, req, &body) {
			return
		}
		r.registrationDo(w, req, 200, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, m *sources.MachineService) (any, error) {
			return m.RevokeCode(ctx, tx, id, req.PathValue("code_id"))
		})
	})
	h["GET /api/v1/registration-codes/{code_id}/uses"] = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		r.registrationDo(w, req, 200, func(ctx context.Context, tx pgx.Tx, id accessport.Identity, m *sources.MachineService) (any, error) {
			items, e := m.CodeUses(ctx, tx, id, req.PathValue("code_id"))
			return map[string]any{"items": items}, e
		})
	})
	return h
}

// registrationCA — анонимно: сертификат УЦ центра и его отпечаток (установщик сверяет отпечаток с введённым).
func (r *Registry) registrationCA() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if r.Machine == nil || r.Machine.CA == nil {
			access.APIError(w, 409, "CAPABILITY_NOT_ENABLED")
			return
		}
		registryJSONStatus(w, 200, map[string]string{"ca_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.Machine.CA.Raw})), "center_fingerprint": r.Machine.Fingerprint})
	})
}

// registrationRegister — анонимно, только TLS: код → источник и grant под CSR машины.
func (r *Registry) registrationRegister() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if r.Machine == nil || r.Machine.Sources == nil {
			access.APIError(w, 409, "CAPABILITY_NOT_ENABLED")
			return
		}
		if req.TLS == nil {
			access.APIError(w, 401, "AUTHENTICATION_REQUIRED")
			return
		}
		var body sources.RegistrationRequest
		if !readOperationBody(w, req, &body) {
			return
		}
		host, _, e := net.SplitHostPort(req.RemoteAddr)
		if e != nil {
			host = req.RemoteAddr
		}
		grant, e := r.Machine.Sources.Register(req.Context(), host, body)
		switch {
		case errors.Is(e, sources.ErrAlreadyRegistered):
			access.APIError(w, 409, "ALREADY_REGISTERED")
		case errors.Is(e, sources.ErrRegistrationCode):
			access.APIError(w, 401, "REGISTRATION_CODE_REJECTED")
		case e != nil:
			r.Machine.fail(w, e)
		default:
			w.Header().Set("Cache-Control", "no-store")
			registryJSONStatus(w, 201, grant)
		}
	})
}
