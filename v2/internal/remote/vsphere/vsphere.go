// Package vsphere — C57.03: коннектор VMware vSphere (vCenter или отдельный ESXi) только на чтение. Через API vSphere
// (SOAP, govmomi) читаются центры обработки данных, кластеры, хосты ESXi, ВМ, хранилища и сети; итог — снимок
// платформы C57 (contracts/c57-platform.schema.json), который collector подписывает и отправляет центру.
//
// Только чтение: используются вход (SessionManager.Login), ContainerView и PropertyCollector.RetrieveProperties и
// выход. Методы, меняющие состояние (питание, конфигурацию, задачи), не вызываются. Учётке достаточно роли «Read-only»,
// распространённой на объекты (Propagate).
//
// Проверка сервера — как у WinRM (C51.03): по CA, заданному администратором, с проверкой имени, либо по закреплённому
// отпечатку SHA-256 сертификата (запоминается при первом подключении). Отключение проверки не поддерживается;
// HTTP-прокси окружения не используется (данные и пароль в прокси не уходят).
package vsphere

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vmware/govmomi/session"
	"github.com/vmware/govmomi/view"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vim25/types"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/remote/tlspin"
)

// Target — адрес API vSphere и способ проверки сервера. Ровно одно из CAPEM (с ServerName) и CertSHA256.
type Target struct {
	Host       string
	Port       int
	User       string
	Password   []byte
	CAPEM      []byte
	ServerName string
	CertSHA256 string
	Timeout    time.Duration // общий предел сбора; 0 — 5 мин
}

var (
	// ErrPolicy — не задан способ проверки сервера.
	ErrPolicy = tlspin.ErrPolicy
	// ErrCertChanged — сертификат сервера не совпал с закреплённым отпечатком.
	ErrCertChanged = tlspin.ErrCertChanged
	// ErrAuth — вход отклонён (неверная учётка или нет прав).
	ErrAuth = errors.New("vsphere: login rejected (auth_failed)")
	// ErrNotVSphere — по адресу нет API vSphere.
	ErrNotVSphere = errors.New("vsphere: no vSphere API at address (not_vsphere)")
)

func tlsConfig(t Target) (*tls.Config, error) {
	return tlspin.Config(t.CAPEM, t.ServerName, t.Host, t.CertSHA256)
}

// FetchCert — сертификат сервера без входа (для закрепления при первом подключении): отпечаток SHA-256 DER.
func FetchCert(host string, port int, serverName string, timeout time.Duration) (string, error) {
	if port == 0 {
		port = 443
	}
	return tlspin.Fetch(host, port, serverName, timeout)
}

// Inventory — прочитанное из vSphere (без секретов).
type Inventory struct {
	About       types.AboutInfo
	Datacenters []Datacenter
	Errors      []string // коды частичного сбора (раздел не прочитан)
}

type Datacenter struct {
	Ref        string
	Name       string
	Clusters   []mo.ClusterComputeResource
	Hosts      []mo.HostSystem
	VMs        []mo.VirtualMachine
	Datastores []mo.Datastore
	Networks   []mo.Network
}

// Collect входит в vSphere, читает объекты и выходит. Ошибка подключения/входа — ошибка; ошибка чтения отдельного
// раздела — код в Inventory.Errors (снимок будет неполным, объекты не помечаются удалёнными).
func Collect(ctx context.Context, t Target) (*Inventory, error) {
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cfg, err := tlsConfig(t)
	if err != nil {
		return nil, err
	}
	port := t.Port
	if port == 0 {
		port = 443
	}
	u := &url.URL{Scheme: "https", Host: net.JoinHostPort(t.Host, strconv.Itoa(port)), Path: vim25.Path}
	sc := soap.NewClient(u, false)
	tr := sc.DefaultTransport()
	tr.Proxy = nil
	tr.TLSClientConfig = cfg
	vc, err := vim25.NewClient(ctx, sc)
	if err != nil {
		return nil, classify(err)
	}
	m := session.NewManager(vc)
	if err = m.Login(ctx, url.UserPassword(t.User, string(t.Password))); err != nil {
		if errors.Is(classify(err), ErrCertChanged) {
			return nil, ErrCertChanged
		}
		return nil, ErrAuth
	}
	defer func() {
		out, c := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer c()
		_ = m.Logout(out)
	}()
	return read(ctx, vc)
}

func classify(err error) error {
	switch {
	case errors.Is(err, ErrCertChanged), strings.Contains(err.Error(), "cert_changed"):
		return ErrCertChanged
	case soap.IsSoapFault(err), strings.Contains(err.Error(), "404"):
		return ErrNotVSphere
	}
	return err
}

// read — чтение объектов по уже открытому сеансу (отдельно — для проверки на симуляторе vcsim).
func read(ctx context.Context, vc *vim25.Client) (*Inventory, error) {
	inv := &Inventory{About: vc.ServiceContent.About, Errors: []string{}}
	vm := view.NewManager(vc)
	root, err := vm.CreateContainerView(ctx, vc.ServiceContent.RootFolder, []string{"Datacenter"}, true)
	if err != nil {
		return nil, err
	}
	var dcs []mo.Datacenter
	err = root.Retrieve(ctx, []string{"Datacenter"}, []string{"name"}, &dcs)
	_ = root.Destroy(ctx)
	if err != nil {
		return nil, err
	}
	sort.Slice(dcs, func(i, j int) bool { return dcs[i].Self.Value < dcs[j].Self.Value })
	for _, dc := range dcs {
		d := Datacenter{Ref: dc.Self.Value, Name: dc.Name}
		part := func(kind string, props []string, dst any) {
			v, e := vm.CreateContainerView(ctx, dc.Self, []string{kind}, true)
			if e == nil {
				e = v.Retrieve(ctx, []string{kind}, props, dst)
				_ = v.Destroy(ctx)
			}
			if e != nil {
				inv.Errors = append(inv.Errors, strings.ToLower(kind)+":unavailable")
			}
		}
		part("ClusterComputeResource", []string{"name", "host"}, &d.Clusters)
		part("HostSystem", []string{"name", "parent", "summary.hardware", "summary.config.product", "summary.runtime.connectionState",
			"summary.runtime.powerState", "summary.runtime.inMaintenanceMode", "hardware.systemInfo", "config.network.pnic", "datastore", "network"}, &d.Hosts)
		part("VirtualMachine", []string{"name", "config.uuid", "config.instanceUuid", "config.template", "config.guestFullName",
			"config.hardware.numCPU", "config.hardware.memoryMB", "config.hardware.device", "runtime.powerState", "runtime.host",
			"guest.hostName", "guest.ipAddress", "guest.toolsRunningStatus", "datastore", "network"}, &d.VMs)
		part("Datastore", []string{"name", "summary"}, &d.Datastores)
		part("Network", []string{"name"}, &d.Networks)
		inv.Datacenters = append(inv.Datacenters, d)
	}
	return inv, nil
}

func lowerUUID(s string) *string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != 36 || strings.Count(s, "-") != 4 || s == "00000000-0000-0000-0000-000000000000" {
		return nil
	}
	return &s
}

func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func optional(s string, n int) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	s = cut(s, n)
	return &s
}

func macNorm(m string) string {
	m = strings.ToLower(strings.NewReplacer("-", "", ":", "").Replace(strings.TrimSpace(m)))
	if len(m) != 12 {
		return ""
	}
	return m[0:2] + ":" + m[2:4] + ":" + m[4:6] + ":" + m[6:8] + ":" + m[8:10] + ":" + m[10:12]
}

func hostSerial(h mo.HostSystem) *string {
	if h.Hardware == nil {
		return nil
	}
	si := h.Hardware.SystemInfo
	if s := optional(si.SerialNumber, 128); s != nil {
		return s
	}
	for _, id := range si.OtherIdentifyingInfo {
		if k := id.IdentifierType.GetElementDescription(); k != nil && (k.Key == "SerialNumberTag" || k.Key == "ServiceTag" || k.Key == "EnclosureSerialNumberTag") {
			if s := optional(id.IdentifierValue, 128); s != nil {
				return s
			}
		}
	}
	return nil
}

// Limits — пределы контракта C57 на снимок.
const (
	maxObjects   = 20000
	maxRelations = 50000
)

// Snapshot — снимок платформы C57 (без tenant/source/generation — их ставит collector). instance — устойчивый ключ
// экземпляра: InstanceUuid vCenter/ESXi, иначе адрес.
func Snapshot(inv *Inventory, address string, target *string, at time.Time) contracts.PlatformSnapshot {
	instance := "vsphere:" + address
	if u := lowerUUID(inv.About.InstanceUuid); u != nil {
		instance = "vsphere:" + *u
	}
	name := cut(address, 256)
	s := contracts.PlatformSnapshot{Major: 1, Target: target, Platform: "vsphere", Instance: cut(instance, 256), InstanceName: name, CollectedAt: at.UTC(),
		Complete: len(inv.Errors) == 0, Objects: []contracts.PlatformObject{}, Relations: []contracts.PlatformRelation{}, Errors: append([]string{}, inv.Errors...)}
	seen := map[string]bool{}
	add := func(o contracts.PlatformObject) bool {
		if seen[o.Ref] {
			return true
		}
		if len(s.Objects) >= maxObjects {
			return false
		}
		if o.MACs == nil {
			o.MACs = []string{}
		}
		if o.Attrs == nil {
			o.Attrs = map[string]any{}
		}
		seen[o.Ref] = true
		s.Objects = append(s.Objects, o)
		return true
	}
	rels := map[contracts.PlatformRelation]bool{}
	rel := func(from, typ, to string) {
		r := contracts.PlatformRelation{From: from, Type: typ, To: to}
		if from == to || rels[r] || !seen[from] || !seen[to] {
			return
		}
		if len(s.Relations) >= maxRelations {
			s.Complete = false
			return
		}
		rels[r] = true
		s.Relations = append(s.Relations, r)
	}
	truncated := false
	ref := func(kind, id string) string { return kind + ":" + id }
	for _, dc := range inv.Datacenters {
		dcRef := ref("datacenter", dc.Ref)
		// сведения об API (vCenter/ESXi, версия) — у объекта ЦОД: у экземпляра платформы своих атрибутов нет
		add(contracts.PlatformObject{Ref: dcRef, Kind: "datacenter", Name: cut(dc.Name, 256), Attrs: map[string]any{"api_type": cut(inv.About.ApiType, 64),
			"api_version": cut(inv.About.Version, 64), "api_build": cut(inv.About.Build, 64), "product": cut(inv.About.FullName, 256)}})
		for _, ds := range dc.Datastores {
			r := ref("datastore", ds.Self.Value)
			attrs := map[string]any{"type": cut(ds.Summary.Type, 64), "capacity_gb": ds.Summary.Capacity >> 30, "free_gb": ds.Summary.FreeSpace >> 30, "accessible": ds.Summary.Accessible}
			if !add(contracts.PlatformObject{Ref: r, Kind: "datastore", Name: cut(ds.Name, 256), Attrs: attrs}) {
				truncated = true
				continue
			}
			rel(r, "located_in", dcRef)
		}
		for _, n := range dc.Networks {
			r := ref("network", n.Self.Value)
			if !add(contracts.PlatformObject{Ref: r, Kind: "network", Name: cut(n.Name, 256), Attrs: map[string]any{"type": cut(n.Self.Type, 64)}}) {
				truncated = true
				continue
			}
			rel(r, "located_in", dcRef)
		}
		for _, c := range dc.Clusters {
			r := ref("cluster", c.Self.Value)
			if !add(contracts.PlatformObject{Ref: r, Kind: "cluster", Name: cut(c.Name, 256), Attrs: map[string]any{"hosts": len(c.Host)}}) {
				truncated = true
				continue
			}
			rel(r, "located_in", dcRef)
		}
		for _, h := range dc.Hosts {
			r := ref("host", h.Self.Value)
			attrs := map[string]any{"hypervisor": "esxi", "connection": string(h.Summary.Runtime.ConnectionState), "power": string(h.Summary.Runtime.PowerState),
				"maintenance": h.Summary.Runtime.InMaintenanceMode}
			var bios *string
			if hw := h.Summary.Hardware; hw != nil {
				attrs["vendor"], attrs["model"] = cut(hw.Vendor, 256), cut(hw.Model, 256)
				attrs["cpu_model"], attrs["cpu_cores"], attrs["cpu_threads"], attrs["memory_mb"] = cut(hw.CpuModel, 256), hw.NumCpuCores, hw.NumCpuThreads, hw.MemorySize>>20
				bios = lowerUUID(hw.Uuid)
			}
			if p := h.Summary.Config.Product; p != nil {
				attrs["os"], attrs["version"], attrs["build"] = cut(p.FullName, 256), cut(p.Version, 64), cut(p.Build, 64)
			}
			if h.Hardware != nil {
				if u := lowerUUID(h.Hardware.SystemInfo.Uuid); u != nil {
					bios = u
				}
			}
			macs := []string{}
			if h.Config != nil && h.Config.Network != nil {
				for _, p := range h.Config.Network.Pnic {
					if m := macNorm(p.Mac); m != "" && len(macs) < 32 {
						macs = append(macs, m)
					}
				}
			}
			hostname := optional(strings.ToLower(h.Name), 255)
			if hostname != nil && net.ParseIP(*hostname) != nil {
				hostname = nil
			}
			if !add(contracts.PlatformObject{Ref: r, Kind: "host", Name: cut(h.Name, 256), BiosUUID: bios, Serial: hostSerial(h), Hostname: hostname, MACs: macs, Attrs: attrs}) {
				truncated = true
				continue
			}
			if h.Parent != nil && h.Parent.Type == "ClusterComputeResource" {
				rel(r, "member_of", ref("cluster", h.Parent.Value))
			}
			rel(r, "located_in", dcRef)
			for _, d := range h.Datastore {
				rel(r, "uses_storage", ref("datastore", d.Value))
			}
			for _, n := range h.Network {
				rel(r, "connected_to", ref("network", n.Value))
			}
		}
		for _, v := range dc.VMs {
			r := ref("vm", v.Self.Value)
			attrs := map[string]any{"state": powerState(v.Runtime.PowerState)}
			var bios *string
			macs := []string{}
			if c := v.Config; c != nil {
				bios = lowerUUID(c.Uuid)
				attrs["instance_uuid"] = cut(strings.ToLower(c.InstanceUuid), 64)
				attrs["template"] = c.Template
				attrs["guest_os"] = cut(c.GuestFullName, 256)
				attrs["vcpu"], attrs["memory_mb"] = c.Hardware.NumCPU, c.Hardware.MemoryMB
				for _, dev := range c.Hardware.Device {
					if nic, ok := dev.(types.BaseVirtualEthernetCard); ok {
						if m := macNorm(nic.GetVirtualEthernetCard().MacAddress); m != "" && len(macs) < 32 {
							macs = append(macs, m)
						}
					}
				}
			}
			var hostname *string
			if g := v.Guest; g != nil {
				hostname = optional(strings.ToLower(g.HostName), 255)
				if ip := strings.TrimSpace(g.IpAddress); ip != "" {
					attrs["ip"] = cut(ip, 64)
				}
				if g.ToolsRunningStatus != "" {
					attrs["tools"] = cut(g.ToolsRunningStatus, 64)
				}
			}
			if !add(contracts.PlatformObject{Ref: r, Kind: "vm", Name: cut(v.Name, 256), BiosUUID: bios, Hostname: hostname, MACs: macs, Attrs: attrs}) {
				truncated = true
				continue
			}
			if v.Runtime.Host != nil {
				rel(r, "runs_on", ref("host", v.Runtime.Host.Value))
			}
			for _, d := range v.Datastore {
				rel(r, "uses_storage", ref("datastore", d.Value))
			}
			for _, n := range v.Network {
				rel(r, "connected_to", ref("network", n.Value))
			}
		}
	}
	if truncated {
		s.Complete = false
		if len(s.Errors) < 32 {
			s.Errors = append(s.Errors, "objects:truncated")
		}
	}
	if len(s.Errors) > 32 {
		s.Errors = s.Errors[:32]
	}
	return s
}

func powerState(p types.VirtualMachinePowerState) string {
	switch p {
	case types.VirtualMachinePowerStatePoweredOn:
		return "running"
	case types.VirtualMachinePowerStatePoweredOff:
		return "off"
	case types.VirtualMachinePowerStateSuspended:
		return "saved"
	}
	return "other"
}
