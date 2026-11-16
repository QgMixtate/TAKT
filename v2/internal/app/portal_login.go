package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
)

// directoryLoginHandler — вход сотрудника на портал обращений учёткой AD (C46.01). Порядок: тот же предел попыток,
// что у обычного входа → ровно одна активная запись оргструктуры с этим логином → пароль проверяет каталог этой
// организации (bind от имени записи пользователя) → GUID записи каталога совпадает с записью оргструктуры →
// пользователь «заявитель» без локального пароля → связь с записью оргструктуры → сессия. Любая неудача — общий
// отказ входа без подробностей (не раскрывает, есть ли логин и какая часть не прошла).
func (r *Registry) directoryLoginHandler(auth *access.HTTP) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		ctx, cancel := context.WithTimeout(req.Context(), 20*time.Second)
		defer cancel()
		if !auth.OriginOK(req) {
			access.Fail(w, access.ErrForbidden)
			return
		}
		var body struct {
			Login    string `json:"login"`
			Password string `json:"password"`
		}
		d := json.NewDecoder(http.MaxBytesReader(w, req.Body, 4096))
		d.DisallowUnknownFields()
		if d.Decode(&body) != nil {
			access.APIError(w, 400, "INVALID_JSON")
			return
		}
		login := strings.TrimSpace(body.Login)
		if i := strings.LastIndex(login, `\`); i >= 0 { // DOMAIN\login → login
			login = login[i+1:]
		}
		if i := strings.Index(login, "@"); i >= 0 { // login@domain → login
			login = login[:i]
		}
		username, ok := access.DirectoryUsername(login)
		if !ok {
			access.Fail(w, access.ErrAuth)
			return
		}
		if e := auth.Throttle(ctx, username); e != nil {
			access.Fail(w, e)
			return
		}
		session, raw, e := r.directoryLogin(ctx, auth, login, body.Password)
		if e != nil {
			if errors.Is(e, access.ErrLimit) {
				access.Fail(w, e)
				return
			}
			access.Fail(w, access.ErrAuth)
			return
		}
		auth.SetSession(w, session, raw)
	}
}

func (r *Registry) directoryLogin(ctx context.Context, auth *access.HTTP, login, password string) (access.Session, string, error) {
	tx, e := r.Pool.Begin(ctx)
	if e != nil {
		return access.Session{}, "", e
	}
	candidates, e := r.Owners.DirectoryLoginCandidates(ctx, tx, login)
	tx.Rollback(ctx)
	if e != nil || len(candidates) != 1 {
		return access.Session{}, "", access.ErrAuth
	}
	c := candidates[0]
	d, _, e := r.directoryFor(ctx, c.Tenant)
	if e != nil || d == nil {
		return access.Session{}, "", access.ErrAuth
	}
	guid, e := d.Authenticate(login, password)
	if e != nil || !strings.EqualFold(guid, c.ExternalID) {
		return access.Session{}, "", access.ErrAuth
	}
	session, raw, e := auth.DirectorySession(ctx, c.Tenant, login)
	if e != nil {
		return access.Session{}, "", e
	}
	tx, e = r.Pool.Begin(ctx)
	if e != nil {
		return access.Session{}, "", e
	}
	defer tx.Rollback(ctx)
	if e = r.Owners.LinkPortalUser(ctx, tx, c.Tenant, c.Subject, session.UserID); e != nil {
		return access.Session{}, "", e // запись уже связана с другой учёткой (оператор входит обычным способом)
	}
	if e = r.Audit.Record(ctx, tx, c.Tenant, session.UserID, "portal.login", "subject", c.Subject); e != nil {
		return access.Session{}, "", e
	}
	return session, raw, tx.Commit(ctx)
}
