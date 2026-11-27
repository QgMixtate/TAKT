//go:build linux

package collecttargets

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/telemetry"
	"github.com/QgMixtate/surveyscan/v2/internal/remote/vsphere"
)

// runVSphere — C57.03: цель vSphere (vCenter или ESXi). Источник-агент не регистрируется: раз в период цели (не чаще
// 15 мин; «Собрать сейчас» перезапускает цикл) collector входит в API только на чтение и отправляет снимок платформы
// от своего имени. Сертификат без PEM закрепляется в центре при первом подключении, как у WinRM.
func (c *Manager) runVSphere(ctx context.Context, t machineTarget) {
	period := time.Duration(max(t.Interval, 900)) * time.Second
	addr := net.JoinHostPort(t.Address, strconv.Itoa(t.Port))
	log := func(s string) { telemetry.Log(os.Stderr, "collector", "target_"+t.ID[:8]+"_vsphere_"+s) }
	for ctx.Err() == nil {
		wait := period
		problem, ok := c.vsphereOnce(ctx, t, addr)
		switch {
		case ok:
			log("snapshot_sent")
			c.report(ctx, t.ID, true, "")
		default:
			log(problem)
			c.report(ctx, t.ID, false, problem)
			if problem != "cert_changed" && problem != "vsphere:auth_failed" {
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

// vsphereOnce — один сбор: код причины (без секретов) или ok.
func (c *Manager) vsphereOnce(ctx context.Context, t machineTarget, addr string) (string, bool) {
	if c.Platform == nil {
		return "collector:platform_unavailable", false
	}
	target := vsphere.Target{Host: t.Address, Port: t.Port, User: t.Username, Timeout: 5 * time.Minute}
	if t.ServerName != nil {
		target.ServerName = *t.ServerName
	}
	switch {
	case t.CAPEM != nil:
		target.CAPEM = []byte(*t.CAPEM)
	default:
		// PEM не задан: сертификат сервера закрепляется в центре при первом подключении; другой — Conflict, сбор
		// остановлен до сброса в Web
		task, cancel := context.WithTimeout(ctx, 20*time.Second)
		fp, err := vsphere.FetchCert(t.Address, t.Port, target.ServerName, 15*time.Second)
		if err != nil {
			cancel()
			return "vsphere:unreachable", false
		}
		code, _, err := c.targetPost(task, "/api/v1/machine/collect-targets/"+t.ID+"/tlscert", map[string]string{"tls_cert_sha256": fp})
		cancel()
		if err == nil && code == 409 {
			return "cert_changed", false
		}
		if err != nil || code != 204 {
			return "collector:cert_not_accepted", false
		}
		target.CertSHA256 = fp
	}
	s, err := c.secret(ctx, t.ID)
	if err != nil || s.Secret.Password == "" {
		return "collector:credential_unavailable", false
	}
	target.Password = []byte(s.Secret.Password)
	inv, err := vsphere.Collect(ctx, target)
	for i := range target.Password {
		target.Password[i] = 0
	}
	switch {
	case errors.Is(err, vsphere.ErrCertChanged):
		return "cert_changed", false
	case errors.Is(err, vsphere.ErrAuth):
		return "vsphere:auth_failed", false
	case errors.Is(err, vsphere.ErrNotVSphere):
		return "vsphere:not_vsphere", false
	case err != nil:
		return "vsphere:unreachable", false
	}
	id := t.ID
	snap := vsphere.Snapshot(inv, addr, &id, time.Now())
	send, done := context.WithTimeout(ctx, time.Minute)
	defer done()
	if err = c.Platform(send, snap); err != nil {
		return "vsphere:snapshot_rejected", false
	}
	return "", true
}
