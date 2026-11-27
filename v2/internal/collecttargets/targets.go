//go:build linux

package collecttargets

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/agent"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/telemetry"
	"github.com/QgMixtate/surveyscan/v2/internal/remote/sshlinux"
	"github.com/QgMixtate/surveyscan/v2/internal/remote/winrminv"
)

// Package collecttargets — C51.03 шаг C: цели удалённого сбора, заведённые в Web. Для каждой цели collector держит отдельную личность агента
// (состояние в своём каталоге учётных данных), регистрирует её по grant центра обычным путём агента через себя
// и собирает узел по SSH/WinRM; учётку берёт у центра по mTLS перед каждым сбором и держит только в памяти.

type machineTarget struct {
	ID         string  `json:"target_id"`
	Kind       string  `json:"kind"`
	Address    string  `json:"address"`
	Port       int     `json:"port"`
	Username   string  `json:"username"`
	HostKey    *string `json:"host_key_sha256"`
	CAPEM      *string `json:"tls_ca_pem"`
	ServerName *string `json:"tls_server_name"`
	CertSHA256 *string `json:"tls_cert_sha256"`
	CertOrigin *string `json:"tls_cert_origin"`
	Transport  *string `json:"winrm_transport"`
	CollectAt  *string `json:"collect_requested_at"` // «Собрать сейчас»: новое значение перезапускает цикл цели — сбор сразу
	Interval   int     `json:"interval_seconds"`
	Source     *string `json:"agent_source_id"`
	State      string  `json:"state"`
	Site       string  `json:"site_id"`
	Scope      string  `json:"network_scope_id"`
	Tenant     string  `json:"tenant_id"`
}

func (t machineTarget) key() string {
	s := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	return strings.Join([]string{t.Kind, t.Address, strconv.Itoa(t.Port), t.Username, s(t.HostKey), s(t.CAPEM), s(t.ServerName), s(t.CertSHA256), s(t.CertOrigin), s(t.Transport), s(t.CollectAt)}, "\x00")
}

// Manager — цели одного collector. Post — запрос к центру по mTLS collector; Listen — слушатель collector для
// встроенных агентов; CollectorSource — личность collector; CA — файл CA; StateDir — каталог учётных данных.
type Manager struct {
	Post            func(ctx context.Context, path string, raw []byte) (int, []byte, error)
	Listen          string
	CollectorSource string
	CA              string
	StateDir        string
	// Platform — C57: отправка снимка платформы (KVM по SSH и др.) с подписью collector; nil — не собирать.
	Platform func(ctx context.Context, s contracts.PlatformSnapshot) error
	set      targetSet
}

type targetRun struct {
	key    string
	cancel context.CancelFunc
}

type targetSet struct {
	mu   sync.Mutex
	runs map[string]targetRun
}

// selfURL — собственный слушатель collector для встроенных агентов целей (имя сервера проверяется по личности
// collector, а не по адресу).
func (c *Manager) selfURL() string {
	host, port, e := net.SplitHostPort(c.Listen)
	if e != nil {
		return ""
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "https://" + net.JoinHostPort(host, port)
}

func (c *Manager) targetPost(ctx context.Context, path string, body any) (int, []byte, error) {
	raw, _ := json.Marshal(body)
	return c.Post(ctx, path, raw)
}

// targetsTick сверяет запущенные цели с целями центра: новые запускает, изменённые перезапускает, снятые — гасит.
// Tick сверяет запущенные цели с целями центра (запрос — в рамках task, цели живут в рамках ctx).
func (c *Manager) Tick(ctx, task context.Context) error {
	code, raw, e := c.targetPost(task, "/api/v1/machine/collect-targets", struct{}{})
	if e != nil {
		return e
	}
	if code == 404 || code == 501 {
		return nil
	}
	if code != 200 {
		return errors.New("collect targets unavailable")
	}
	var got struct {
		Items []machineTarget `json:"items"`
	}
	if e = json.Unmarshal(raw, &got); e != nil {
		return e
	}
	set := &c.set
	set.mu.Lock()
	if set.runs == nil {
		set.runs = map[string]targetRun{}
	}
	defer set.mu.Unlock()
	seen := map[string]bool{}
	for _, t := range got.Items {
		if !identifier.Valid(t.ID) || (t.Kind != "ssh" && t.Kind != "winrm" && t.Kind != "snmp" && t.Kind != "vsphere") {
			continue
		}
		seen[t.ID] = true
		if r, ok := set.runs[t.ID]; ok {
			if r.key == t.key() {
				continue
			}
			r.cancel()
		}
		runCtx, cancel := context.WithCancel(ctx)
		set.runs[t.ID] = targetRun{key: t.key(), cancel: cancel}
		go c.runTarget(runCtx, t)
	}
	for id, r := range set.runs {
		if !seen[id] {
			r.cancel()
			delete(set.runs, id)
		}
	}
	return nil
}

func (c *Manager) report(ctx context.Context, target string, ok bool, problem string) {
	task, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_, _, _ = c.targetPost(task, "/api/v1/machine/collect-targets/"+target+"/report", map[string]any{"ok": ok, "problem": problem})
}

type issuedSecret struct {
	Kind     string `json:"kind"`
	Username string `json:"username"`
	Secret   struct {
		Password     string `json:"password"`
		PrivateKey   string `json:"private_key"`
		Passphrase   string `json:"passphrase"`
		AuthProtocol string `json:"auth_protocol"`
		AuthKey      string `json:"auth_key"`
		PrivProtocol string `json:"priv_protocol"`
		PrivKey      string `json:"priv_key"`
	} `json:"secret"`
}

func (c *Manager) secret(ctx context.Context, target string) (issuedSecret, error) {
	var out issuedSecret
	code, raw, e := c.targetPost(ctx, "/api/v1/machine/collect-targets/"+target+"/secret", struct{}{})
	if e != nil || code != 200 {
		return out, errors.New("credential not issued")
	}
	return out, json.Unmarshal(raw, &out)
}

// enrollTarget — личность агента цели: подготовка (ключи и CSR в каталоге цели), grant центра, регистрация.
func (c *Manager) enrollTarget(ctx context.Context, cfg agent.Config, t machineTarget) error {
	if _, e := os.Stat(filepath.Join(cfg.State, "identity.json")); e == nil {
		return nil
	}
	prep, e := agent.Prepare(cfg)
	if e != nil {
		return e
	}
	code, raw, e := c.targetPost(ctx, "/api/v1/machine/collect-targets/"+t.ID+"/grant", map[string]string{"source_id": prep.Source, "csr_sha256": prep.Hash, "signing_public_key": prep.Public})
	if e != nil || code != 200 {
		return errors.New("target grant not issued")
	}
	var grant contracts.EnrollmentGrant
	if e = json.Unmarshal(raw, &grant); e != nil {
		return e
	}
	return agent.Enroll(ctx, cfg, grant)
}

func (c *Manager) runTarget(ctx context.Context, t machineTarget) {
	// паника в сборе одной цели не должна останавливать collector (и доставку всех источников): ошибка цели видна
	// в Web как internal_error, цель перезапускается через минуту
	defer func() {
		if r := recover(); r != nil {
			telemetry.Log(os.Stderr, "collector", "target_"+t.ID[:8]+"_panic")
			c.report(context.WithoutCancel(ctx), t.ID, false, "internal_error")
			time.AfterFunc(time.Minute, func() {
				if ctx.Err() == nil {
					go c.runTarget(ctx, t)
				}
			})
		}
	}()
	if t.Kind == "vsphere" { // C57.03: без личности агента — только снимок платформы
		c.runVSphere(ctx, t)
		return
	}
	platform := contracts.InventoryPlatformLinux12
	if t.Kind == "winrm" {
		platform = contracts.InventoryPlatform12
	} else if t.Kind == "snmp" {
		platform = contracts.InventoryPlatformNetwork12
	}
	state := filepath.Join(c.StateDir, "targets", t.ID)
	// №56: центр снял привязку (цель включена заново) — прежняя личность цели недействительна, регистрация с нуля
	if _, e := os.Stat(filepath.Join(state, "identity.json")); e == nil && t.Source == nil {
		telemetry.Log(os.Stderr, "collector", "target_"+t.ID[:8]+"_state_reset")
		if e = os.RemoveAll(state); e != nil {
			telemetry.Log(os.Stderr, "collector", "target_state_unavailable")
			return
		}
	}
	if e := os.MkdirAll(state, 0o700); e != nil {
		telemetry.Log(os.Stderr, "collector", "target_state_unavailable")
		return
	}
	cfg := agent.Config{Tenant: t.Tenant, Site: t.Site, Scope: t.Scope, CollectorURL: c.selfURL(), CollectorSource: c.CollectorSource, CA: c.CA,
		State: state, InventorySeconds: max(t.Interval, 300), HeartbeatSeconds: 60, // стенд №12: центр ждёт пульс раз в 60 с (STALE после 3 периодов)
		Jitter: 10, Limit: 16 << 20, InventoryPlatform: platform}
	var targetProblem atomic.Value // последний код отказа подключения цели (пишет сбор, читает отчёт)
	targetProblem.Store("")
	pinned := "" // отпечаток сертификата WinRM, с которым запущен сбор (цель без PEM)
	report := func(s string) {
		if !strings.HasPrefix(s, "detail:") {
			telemetry.Log(os.Stderr, "collector", "target_"+t.ID[:8]+"_"+s) // состояние цикла цели (без секретов)
		}
		switch {
		case s == "inventory_queued":
			targetProblem.Store("") // успешный сбор: прежняя причина отказа больше не актуальна
			c.report(ctx, t.ID, true, "")
		case s == "inventory_failed" || s == "inventory_collection_deadline":
			// закреплённый сертификат WinRM сменился во время работы: показать причину, а не общий отказ
			if pinned != "" {
				if fp, err := winrminv.FetchCert(t.Address, t.Port, "", 15*time.Second); err == nil && fp != pinned {
					c.report(ctx, t.ID, false, "cert_changed")
					return
				}
			}
			if code, _ := targetProblem.Load().(string); code != "" && !strings.HasSuffix(code, ":") {
				c.report(ctx, t.ID, false, code) // причина отказа SSH/WinRM фиксированным кодом
				return
			}
			c.report(ctx, t.ID, false, s)
		}
	}
	for ctx.Err() == nil {
		e := c.enrollTarget(ctx, cfg, t)
		if e == nil {
			c.report(ctx, t.ID, false, "") // регистрация завершена: центр переводит цель в active
			addr := net.JoinHostPort(t.Address, strconv.Itoa(t.Port))
			switch t.Kind {
			case "ssh":
				fetch := func(ctx context.Context) (sshlinux.Secret, error) {
					s, err := c.secret(ctx, t.ID)
					out := sshlinux.Secret{Password: s.Secret.Password, Passphrase: s.Secret.Passphrase}
					if s.Secret.PrivateKey != "" {
						out.PrivateKeyPEM = []byte(s.Secret.PrivateKey)
					}
					return out, err
				}
				target := agent.SSHTarget{Addr: addr, User: t.Username, Secret: fetch, Problem: func(code string) { targetProblem.Store("ssh:" + code) }}
				if t.HostKey != nil {
					target.HostKeySHA256 = *t.HostKey
				} else {
					// отпечаток не задан: читаем ключ хоста без входа и закрепляем его на центре (как known_hosts);
					// при смене ключа центр отвечает Conflict, сбор останавливается до сброса в Web
					task, cancel := context.WithTimeout(ctx, 20*time.Second)
					fp, err := sshlinux.FetchHostKey(task, addr, 15*time.Second)
					if err == nil {
						var code int
						code, _, err = c.targetPost(task, "/api/v1/machine/collect-targets/"+t.ID+"/hostkey", map[string]string{"host_key_sha256": fp})
						if err == nil && code == 409 {
							err = errHostKeyChanged
						} else if err == nil && code != 204 {
							err = errors.New("host key not accepted")
						}
					}
					cancel()
					if err != nil {
						e = err
						break
					}
					target.HostKeySHA256 = fp
				}
				kvm, stopKVM := context.WithCancel(ctx)
				go c.kvmLoop(kvm, t, target.HostKeySHA256, fetch)
				e = agent.RunSSH12(ctx, cfg, target, report)
				stopKVM()
			case "winrm":
				fetch := func(ctx context.Context) ([]byte, error) {
					s, err := c.secret(ctx, t.ID)
					return []byte(s.Secret.Password), err
				}
				target := agent.WinRMTarget{Host: t.Address, Port: t.Port, User: t.Username, Password: fetch, Problem: func(code string) { targetProblem.Store("winrm:" + code) }}
				if t.CAPEM != nil {
					target.CAPEM = []byte(*t.CAPEM)
				}
				if t.ServerName != nil {
					target.ServerName = *t.ServerName
				}
				if t.Transport != nil && *t.Transport == "http_kerberos" {
					// Kerberos по имени ПК: сертификаты не используются, сообщения шифруются Kerberos
					if t.ServerName == nil {
						e = errors.New("winrm kerberos target without PC name")
						break
					}
					target.Kerberos = true
					hv, stopHV := context.WithCancel(ctx)
					go c.hypervLoop(hv, t, target)
					e = agent.RunWinRM12(ctx, cfg, target, report)
					stopHV()
					break
				}
				if t.CAPEM == nil && t.CertOrigin != nil && (*t.CertOrigin == "admin" || *t.CertOrigin == "domain_ca") {
					e = errors.New("winrm CA certificate missing") // не подменять проверку по CA запоминанием
					break
				}
				if t.CAPEM == nil {
					// PEM не задан: сертификат сервера закрепляется в центре при первом подключении и сверяется при
					// каждом запуске цели; другой сертификат — Conflict, сбор остановлен до сброса в Web
					task, cancel := context.WithTimeout(ctx, 20*time.Second)
					fp, err := winrminv.FetchCert(t.Address, t.Port, target.ServerName, 15*time.Second)
					if err == nil {
						var code int
						code, _, err = c.targetPost(task, "/api/v1/machine/collect-targets/"+t.ID+"/tlscert", map[string]string{"tls_cert_sha256": fp})
						if err == nil && code == 409 {
							err = errCertChanged
						} else if err == nil && code != 204 {
							err = errors.New("certificate not accepted")
						}
					}
					cancel()
					if err != nil {
						e = err
						break
					}
					target.CertSHA256 = fp
					pinned = fp
				}
				hv, stopHV := context.WithCancel(ctx)
				go c.hypervLoop(hv, t, target)
				e = agent.RunWinRM12(ctx, cfg, target, report)
				stopHV()
			case "snmp":
				// протоколы известны только вместе с ключами: первая выдача учётки — до запуска цикла
				first, err := c.secret(ctx, t.ID)
				if err != nil {
					e = err
					break
				}
				keys := func(ctx context.Context) ([]byte, []byte, error) {
					s, err := c.secret(ctx, t.ID)
					return []byte(s.Secret.AuthKey), []byte(s.Secret.PrivKey), err
				}
				e = agent.RunSNMP12(ctx, cfg, agent.SNMPTarget{Addr: addr, User: t.Username, AuthProto: first.Secret.AuthProtocol, PrivProto: first.Secret.PrivProtocol, Keys: keys}, report)
			}
		}
		if ctx.Err() != nil {
			return
		}
		if e != nil {
			problem := "collector:" + shortError(e)
			if code, _ := targetProblem.Load().(string); code != "" && !strings.HasSuffix(code, ":") {
				problem = code // №56: причина отказа подключения (TLS/Kerberos/SSH) и при отказе запуска цикла
			}
			if errors.Is(e, errHostKeyChanged) || errors.Is(e, errCertChanged) {
				problem = e.Error() // код показывается в Web как есть: ключ/сертификат сменился, нужен сброс
			}
			c.report(ctx, t.ID, false, problem)
			telemetry.Log(os.Stderr, "collector", "target_run_failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}
}

var (
	errHostKeyChanged = errors.New("host_key_changed")
	errCertChanged    = errors.New("cert_changed")
)

func shortError(e error) string {
	var st *agent.StageError
	if errors.As(e, &st) {
		return "stage" + strconv.Itoa(int(st.Code))
	}
	return "failed"
}

// kvmLoop — C57.02: на SSH-цели раз в период (не чаще 15 мин) пробует `virsh --readonly`; есть libvirt и права на
// чтение — снимок платформы KVM уходит центру с подписью collector. Нет libvirt — тихо, повтор через 6 ч.
func (c *Manager) kvmLoop(ctx context.Context, t machineTarget, hostKey string, fetch func(context.Context) (sshlinux.Secret, error)) {
	if c.Platform == nil || hostKey == "" {
		return
	}
	period := time.Duration(max(t.Interval, 900)) * time.Second
	wait := 45 * time.Second
	addr := net.JoinHostPort(t.Address, strconv.Itoa(t.Port))
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = period
		secret, e := fetch(ctx)
		if e != nil {
			continue
		}
		host, e := sshlinux.CollectKVM(ctx, sshlinux.Target{Addr: addr, User: t.Username, HostKeySHA256: hostKey}, secret, sshlinux.Policy{TotalDeadline: 5 * time.Minute})
		if errors.Is(e, sshlinux.ErrNoLibvirt) {
			wait = 6 * time.Hour
			continue
		}
		if e != nil {
			telemetry.Log(os.Stderr, "collector", "target_"+t.ID[:8]+"_kvm_unavailable")
			continue
		}
		id := t.ID
		snap := sshlinux.KVMSnapshot(host, "ssh:"+addr, &id, time.Now())
		send, done := context.WithTimeout(ctx, time.Minute)
		if e = c.Platform(send, snap); e != nil {
			telemetry.Log(os.Stderr, "collector", "target_"+t.ID[:8]+"_kvm_snapshot_rejected")
		} else {
			telemetry.Log(os.Stderr, "collector", "target_"+t.ID[:8]+"_kvm_snapshot_sent")
		}
		done()
	}
}

// hypervLoop — C57.02: на WinRM-цели раз в период (не чаще 15 мин) пробует CIM Hyper-V; роль есть и права на чтение —
// снимок платформы Hyper-V уходит центру с подписью collector. Нет роли — тихо, повтор через 6 ч.
func (c *Manager) hypervLoop(ctx context.Context, t machineTarget, target agent.WinRMTarget) {
	if c.Platform == nil {
		return
	}
	period := time.Duration(max(t.Interval, 900)) * time.Second
	wait := 60 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = period
		host, e := agent.HyperVOnce(ctx, target)
		if errors.Is(e, winrminv.ErrNoHyperV) {
			wait = 6 * time.Hour
			continue
		}
		if e != nil {
			telemetry.Log(os.Stderr, "collector", "target_"+t.ID[:8]+"_hyperv_unavailable")
			continue
		}
		id := t.ID
		snap := winrminv.HyperVSnapshot(host, "winrm:"+net.JoinHostPort(t.Address, strconv.Itoa(t.Port)), &id, time.Now())
		send, done := context.WithTimeout(ctx, time.Minute)
		if e = c.Platform(send, snap); e != nil {
			telemetry.Log(os.Stderr, "collector", "target_"+t.ID[:8]+"_hyperv_snapshot_rejected")
		} else {
			telemetry.Log(os.Stderr, "collector", "target_"+t.ID[:8]+"_hyperv_snapshot_sent")
		}
		done()
	}
}
