package agent

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/enrollpin"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// Установка по коду (C52.01): «адрес collector площадки + код + отпечаток центра» → готовая конфигурация, CA,
// подготовленная личность и enroll. Отпечаток — SHA-256 сертификата УЦ центра из Web; без совпадения дальше не идём.

type RegisterOptions struct {
	CollectorURL string
	Code         string
	Fingerprint  string
	ConfigPath   string // куда записать конфигурацию агента (0600)
	StateDir     string // каталог состояния (абсолютный)
	Hostname     string
}

type registrationResult struct {
	Grant           contracts.EnrollmentGrant `json:"grant"`
	Tenant          string                    `json:"tenant_id"`
	Site            string                    `json:"site_id"`
	Scope           string                    `json:"network_scope_id"`
	CollectorSource *string                   `json:"collector_source_id"`
}

// Register — полная установка агента по коду: CA → prepare → регистрация → конфигурация → enroll.
func Register(ctx context.Context, o RegisterOptions) error {
	u, e := url.Parse(o.CollectorURL)
	if e != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("адрес collector: https://host:port")
	}
	if !filepath.IsAbs(o.StateDir) || !filepath.IsAbs(o.ConfigPath) {
		return errors.New("каталог состояния и путь конфигурации должны быть абсолютными")
	}
	if _, e = os.Stat(o.ConfigPath); e == nil {
		return errors.New("конфигурация уже существует: агент зарегистрирован (удалите её только для переустановки)")
	}
	ca, caPEM, e := enrollpin.FetchPinnedCA(ctx, o.CollectorURL, o.Fingerprint)
	if e != nil {
		return e
	}
	if e = ensureStateDir(o.StateDir); e != nil {
		return e
	}
	caPath := filepath.Join(o.StateDir, "ca.pem")
	if e = os.WriteFile(caPath, caPEM, 0o600); e != nil {
		return e
	}
	platform := contracts.InventoryPlatformLinux12
	if runtime.GOOS == "windows" {
		platform = contracts.InventoryPlatform12
	}
	c := Config{CollectorURL: strings.TrimRight(o.CollectorURL, "/"), CA: caPath, State: o.StateDir}
	prep, e := Prepare(c)
	if e != nil {
		return e
	}
	host := o.Hostname
	if host == "" {
		host, _ = os.Hostname()
	}
	var result registrationResult
	if e = enrollpin.PostRegistration(ctx, o.CollectorURL, ca, "", map[string]string{"registration_code": o.Code, "source_id": prep.Source, "csr_sha256": prep.Hash,
		"signing_public_key": prep.Public, "hostname": host, "inventory_platform": platform}, &result); e != nil {
		return e
	}
	if result.CollectorSource == nil || !identifier.Valid(*result.CollectorSource) || result.Grant.SourceID != prep.Source {
		return errors.New("код выдан не для агента")
	}
	c.Tenant, c.Site, c.Scope, c.CollectorSource = result.Tenant, result.Site, result.Scope, *result.CollectorSource
	// grant сохраняется до enroll: при обрыве повтор enroll возможен, повтор регистрации тем же CSR — нет
	if e = saveJSON(filepath.Join(o.StateDir, "registration-grant.json"), result.Grant); e != nil {
		return e
	}
	if e = saveJSON(o.ConfigPath, c); e != nil {
		return e
	}
	if c, e = ReadConfig(o.ConfigPath); e != nil {
		return e
	}
	if e = Enroll(ctx, c, result.Grant); e != nil {
		return fmt.Errorf("регистрация прошла, enroll не завершён (повторите `enroll --grant-file %s`): %w", filepath.Join(o.StateDir, "registration-grant.json"), e)
	}
	_ = os.Remove(filepath.Join(o.StateDir, "registration-grant.json"))
	return nil
}
