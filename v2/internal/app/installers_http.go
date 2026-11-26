package app

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/QgMixtate/surveyscan/v2/internal/installers"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
)

// Файлы установки из подписанного выпуска (C52.04): список и скачивание — администратор и оператор
// (installers:download); каждое скачивание — в аудите. Файл отдаётся только после сверки с подписанным manifest.

type installersList struct {
	Available         bool              `json:"available"`
	Reason            string            `json:"reason,omitempty"`
	Version           string            `json:"release_version,omitempty"`
	ManifestSHA256    string            `json:"manifest_sha256,omitempty"`
	SignatureVerified bool              `json:"signature_verified"`
	Files             []installers.File `json:"files"`
}

func (r *Registry) installersHandlers() map[string]http.Handler {
	h := map[string]http.Handler{}
	h["GET /api/v1/installers"] = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		out := installersList{Files: []installers.File{}}
		switch c := r.Installers; {
		case c == nil && r.InstallersError != "":
			out.Reason = r.InstallersError
		case c == nil:
			out.Reason = "RELEASE_NOT_INSTALLED"
		case len(c.Files) == 0:
			out.Reason, out.Version, out.ManifestSHA256, out.SignatureVerified = "NO_INSTALLERS_IN_RELEASE", c.Version, c.ManifestSHA256, c.SignatureVerified
		default:
			out = installersList{Available: true, Version: c.Version, ManifestSHA256: c.ManifestSHA256, SignatureVerified: c.SignatureVerified, Files: c.Files}
		}
		w.Header().Set("Cache-Control", "no-store")
		registryJSONStatus(w, 200, out)
	})
	h["GET /api/v1/installers/{name}"] = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		if r.Installers == nil {
			access.APIError(w, 404, "NOT_FOUND")
			return
		}
		name := req.PathValue("name")
		body, f, e := r.Installers.Read(name)
		if errors.Is(e, installers.ErrNotFound) {
			access.APIError(w, 404, "NOT_FOUND")
			return
		}
		if e != nil { // файл на диске не совпал с подписанным выпуском — не отдаём
			access.APIError(w, 409, "INSTALLER_INTEGRITY_FAILED")
			return
		}
		// аудит до отдачи: скачивание без записи не происходит
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		tx, e := r.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if e != nil {
			registryError(w, e)
			return
		}
		defer tx.Rollback(ctx)
		if e = (audit.Store{}).Record(ctx, tx, id.TenantID, id.UserID, "installer.downloaded", "installer", f.Name); e == nil {
			e = tx.Commit(ctx)
		}
		if e != nil {
			registryError(w, e)
			return
		}
		// файлы до десятков МБ: общий WriteTimeout сервера (10 с) мал для медленного канала площадки
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Minute))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+f.Name+`"`)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Installer-SHA256", f.SHA256)
		w.WriteHeader(200)
		_, _ = w.Write(body)
	})
	return h
}
