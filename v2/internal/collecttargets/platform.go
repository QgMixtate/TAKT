//go:build linux

package collecttargets

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/telemetry"
	"github.com/QgMixtate/surveyscan/v2/internal/remote/ovirt"
	"github.com/QgMixtate/surveyscan/v2/internal/remote/tlspin"
	"github.com/QgMixtate/surveyscan/v2/internal/remote/vsphere"
)

// runPlatform — C57.03: цель платформы (vsphere — vCenter/ESXi, ovirt — engine oVirt/zVirt). Источник-агент не
// регистрируется: раз в период цели (не чаще 15 мин; «Собрать сейчас» перезапускает цикл) collector входит в API
// только на чтение и отправляет снимок платформы от своего имени. Сертификат без PEM закрепляется в центре при
// первом подключении, как у WinRM.
func (c *Manager) runPlatform(ctx context.Context, t machineTarget) {
	period := time.Duration(max(t.Interval, 900)) * time.Second
	addr := net.JoinHostPort(t.Address, strconv.Itoa(t.Port))
	log := func(s string) { telemetry.Log(os.Stderr, "collector", "target_"+t.ID[:8]+"_"+t.Kind+"_"+s) }
	for ctx.Err() == nil {
		wait := period
		problem, ok := c.platformOnce(ctx, t, addr)
		if ok {
			log("snapshot_sent")
			c.report(ctx, t.ID, true, "")
		} else {
			log(problem)
			c.report(ctx, t.ID, false, problem)
			if problem != "cert_changed" && problem != t.Kind+":auth_failed" {
				wait = min(period, 5*time.Minute) // сеть/сбой центра — повтор раньше периода
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// platformOnce — один сбор: код причины (без секретов) или ok.
func (c *Manager) platformOnce(ctx context.Context, t machineTarget, addr string) (string, bool) {
	if c.Platform == nil {
		return "collector:platform_unavailable", false
	}
	var caPEM []byte
	serverName, pin := "", ""
	if t.ServerName != nil {
		serverName = *t.ServerName
	}
	if t.CAPEM != nil {
		caPEM = []byte(*t.CAPEM)
	} else {
		// PEM не задан: сертификат сервера закрепляется в центре при первом подключении; другой — Conflict, сбор
		// остановлен до сброса в Web
		fp, err := tlspin.Fetch(t.Address, t.Port, serverName, 15*time.Second)
		if err != nil {
			return t.Kind + ":unreachable", false
		}
		task, cancel := context.WithTimeout(ctx, 20*time.Second)
		code, _, err := c.targetPost(task, "/api/v1/machine/collect-targets/"+t.ID+"/tlscert", map[string]string{"tls_cert_sha256": fp})
		cancel()
		if err == nil && code == 409 {
			return "cert_changed", false
		}
		if err != nil || code != 204 {
			return "collector:cert_not_accepted", false
		}
		pin = fp
	}
	s, err := c.secret(ctx, t.ID)
	if err != nil || s.Secret.Password == "" {
		return "collector:credential_unavailable", false
	}
	password := []byte(s.Secret.Password)
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()
	id := t.ID
	var snap contracts.PlatformSnapshot
	switch t.Kind {
	case "vsphere":
		inv, err := vsphere.Collect(ctx, vsphere.Target{Host: t.Address, Port: t.Port, User: t.Username, Password: password, CAPEM: caPEM, ServerName: serverName, CertSHA256: pin, Timeout: 5 * time.Minute})
		if code := platformProblem(t.Kind, err, vsphere.ErrAuth, vsphere.ErrNotVSphere); code != "" {
			return code, false
		}
		snap = vsphere.Snapshot(inv, addr, &id, time.Now())
	case "ovirt":
		inv, err := ovirt.Collect(ctx, ovirt.Target{Host: t.Address, Port: t.Port, User: t.Username, Password: password, CAPEM: caPEM, ServerName: serverName, CertSHA256: pin, Timeout: 5 * time.Minute})
		if code := platformProblem(t.Kind, err, ovirt.ErrAuth, ovirt.ErrNotOVirt); code != "" {
			return code, false
		}
		snap = ovirt.Snapshot(inv, addr, &id, time.Now())
	default:
		return "collector:unsupported_kind", false
	}
	send, done := context.WithTimeout(ctx, time.Minute)
	defer done()
	if err = c.Platform(send, snap); err != nil {
		return t.Kind + ":snapshot_rejected", false
	}
	return "", true
}

// platformProblem — код причины в Web: cert_changed, <вид>:auth_failed, <вид>:not_platform, <вид>:unreachable.
func platformProblem(kind string, err, auth, notPlatform error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, tlspin.ErrCertChanged):
		return "cert_changed"
	case errors.Is(err, auth):
		return kind + ":auth_failed"
	case errors.Is(err, notPlatform):
		return kind + ":not_platform"
	}
	return kind + ":unreachable"
}
