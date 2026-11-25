package sshlinux

import (
	"context"
	"encoding/xml"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
)

// C57.02 — KVM/QEMU по SSH: только `virsh --readonly` к qemu:///system (ничего не меняет на хосте). Нет libvirt или
// нет прав на чтение — ErrNoLibvirt, цель продолжает собираться обычным SSH-сбором. UUID домена libvirt = SMBIOS UUID
// гостя (по умолчанию), поэтому ВМ сопоставляется с активом агента/SSH внутри гостя.

var ErrNoLibvirt = errors.New("ssh: libvirt is not available")

const (
	virsh        = "LC_ALL=C virsh --readonly -c qemu:///system "
	cmdVirshVer  = virsh + "version"
	cmdNodeInfo  = virsh + "nodeinfo"
	cmdListUUIDs = virsh + "list --all --uuid"
	cmdNets      = virsh + "net-list --all --name"
	cmdPools     = virsh + "pool-list --all --name"
	maxDomains   = 1000
)

var (
	uuidLine = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	nameLine = regexp.MustCompile(`^[A-Za-z0-9._:@+-]{1,128}$`)
)

// KVMDomain — разобранный `virsh dumpxml` и состояние домена.
type KVMDomain struct {
	UUID     string
	Name     string
	State    string
	VCPU     int
	MemoryMB int
	MACs     []string
	Networks []string // сети libvirt (interface type=network)
	Bridges  []string // мосты (interface type=bridge)
	Disks    int
	Pools    []string // пулы хранения дисков (source pool=…)
	OS       string   // тип машины (hvm, arch)
}

type domainXML struct {
	UUID   string `xml:"uuid"`
	Name   string `xml:"name"`
	Memory struct {
		Unit  string `xml:"unit,attr"`
		Value string `xml:",chardata"`
	} `xml:"memory"`
	VCPU string `xml:"vcpu"`
	OS   struct {
		Type struct {
			Arch  string `xml:"arch,attr"`
			Value string `xml:",chardata"`
		} `xml:"type"`
	} `xml:"os"`
	Devices struct {
		Interfaces []struct {
			Type string `xml:"type,attr"`
			MAC  struct {
				Address string `xml:"address,attr"`
			} `xml:"mac"`
			Source struct {
				Network string `xml:"network,attr"`
				Bridge  string `xml:"bridge,attr"`
			} `xml:"source"`
		} `xml:"interface"`
		Disks []struct {
			Device string `xml:"device,attr"`
			Source struct {
				Pool string `xml:"pool,attr"`
			} `xml:"source"`
		} `xml:"disk"`
	} `xml:"devices"`
}

// ParseDomainXML разбирает `virsh dumpxml` (без внешних сущностей: encoding/xml их не раскрывает).
func ParseDomainXML(raw string) (KVMDomain, error) {
	var d domainXML
	if e := xml.Unmarshal([]byte(raw), &d); e != nil || !uuidLine.MatchString(strings.TrimSpace(d.UUID)) {
		return KVMDomain{}, errors.New("kvm: invalid domain xml")
	}
	out := KVMDomain{UUID: strings.ToLower(strings.TrimSpace(d.UUID)), Name: strings.TrimSpace(d.Name), MACs: []string{}, Networks: []string{}, Bridges: []string{}, Pools: []string{}}
	out.VCPU, _ = strconv.Atoi(strings.TrimSpace(d.VCPU))
	if n, e := strconv.ParseInt(strings.TrimSpace(d.Memory.Value), 10, 64); e == nil {
		switch strings.ToLower(d.Memory.Unit) {
		case "", "kib", "k":
			out.MemoryMB = int(n / 1024)
		case "mib", "m":
			out.MemoryMB = int(n)
		case "gib", "g":
			out.MemoryMB = int(n * 1024)
		case "b", "bytes":
			out.MemoryMB = int(n >> 20)
		}
	}
	if t := strings.TrimSpace(d.OS.Type.Value); t != "" {
		out.OS = t
		if d.OS.Type.Arch != "" {
			out.OS += " " + d.OS.Type.Arch
		}
	}
	for _, i := range d.Devices.Interfaces {
		if m := strings.ToLower(strings.TrimSpace(i.MAC.Address)); m != "" {
			out.MACs = append(out.MACs, m)
		}
		if i.Source.Network != "" {
			out.Networks = append(out.Networks, i.Source.Network)
		}
		if i.Source.Bridge != "" {
			out.Bridges = append(out.Bridges, i.Source.Bridge)
		}
	}
	for _, d := range d.Devices.Disks {
		if d.Device == "" || d.Device == "disk" {
			out.Disks++
			if d.Source.Pool != "" {
				out.Pools = append(out.Pools, d.Source.Pool)
			}
		}
	}
	return out, nil
}

// ParseNodeInfo разбирает `virsh nodeinfo` (CPU, ядра, память).
func ParseNodeInfo(raw string) map[string]any {
	out := map[string]any{}
	for _, line := range strings.Split(raw, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "CPU model":
			out["cpu_arch"] = v
		case "CPU(s)":
			if n, e := strconv.Atoi(v); e == nil {
				out["cpus"] = n
			}
		case "CPU socket(s)":
			if n, e := strconv.Atoi(v); e == nil {
				out["sockets"] = n
			}
		case "Memory size":
			f := strings.Fields(v)
			if len(f) > 0 {
				if n, e := strconv.ParseInt(f[0], 10, 64); e == nil {
					out["memory_mb"] = int(n / 1024)
				}
			}
		}
	}
	return out
}

func lines(raw string, valid *regexp.Regexp) []string {
	out := []string{}
	for _, l := range strings.Split(raw, "\n") {
		if l = strings.TrimSpace(l); l != "" && valid.MatchString(l) {
			out = append(out, l)
		}
	}
	return out
}

// KVMHost — результат сбора KVM одного хоста.
type KVMHost struct {
	Hostname string
	Version  string
	Node     map[string]any
	Domains  []KVMDomain
	Networks []string
	Pools    []string
	Errors   []string
}

// CollectKVM подключается по SSH и собирает хост KVM только командами `virsh --readonly`.
func CollectKVM(ctx context.Context, t Target, secret Secret, p Policy) (*KVMHost, error) {
	p = p.withDefaults()
	ctx, cancel := context.WithTimeout(ctx, p.TotalDeadline)
	defer cancel()
	client, err := Connect(ctx, t, secret, p)
	if err != nil {
		return nil, err
	}
	var closeOnce sync.Once
	closeClient := func() { closeOnce.Do(func() { client.Close() }) }
	defer closeClient()
	stop := context.AfterFunc(ctx, closeClient)
	defer stop()
	s := session{client: client, policy: p}
	ver, ok := s.run(ctx, cmdVirshVer)
	if !ok || !strings.Contains(ver, "hypervisor") && !strings.Contains(ver, "library") {
		return nil, ErrNoLibvirt
	}
	out := &KVMHost{Errors: []string{}}
	for _, l := range strings.Split(ver, "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok && strings.Contains(strings.ToLower(k), "running hypervisor") {
			out.Version = strings.TrimSpace(v)
		}
	}
	if h, ok := s.run(ctx, cmdHostname); ok {
		out.Hostname = strings.TrimSpace(h)
	}
	if n, ok := s.run(ctx, cmdNodeInfo); ok {
		out.Node = ParseNodeInfo(n)
	} else {
		out.Node = map[string]any{}
		out.Errors = append(out.Errors, "nodeinfo:unavailable")
	}
	list, ok := s.run(ctx, cmdListUUIDs)
	if !ok {
		return nil, ErrNoLibvirt
	}
	uuids := lines(list, uuidLine)
	sort.Strings(uuids)
	if len(uuids) > maxDomains {
		uuids, out.Errors = uuids[:maxDomains], append(out.Errors, "domains:truncated")
	}
	for _, u := range uuids {
		raw, ok := s.run(ctx, virsh+"dumpxml "+u)
		if !ok {
			out.Errors = append(out.Errors, "dumpxml:unavailable")
			continue
		}
		d, e := ParseDomainXML(raw)
		if e != nil {
			out.Errors = append(out.Errors, "dumpxml:invalid")
			continue
		}
		if st, ok := s.run(ctx, virsh+"domstate "+u); ok {
			d.State = strings.TrimSpace(strings.SplitN(st, "\n", 2)[0])
		}
		out.Domains = append(out.Domains, d)
	}
	if n, ok := s.run(ctx, cmdNets); ok {
		out.Networks = lines(n, nameLine)
	}
	if n, ok := s.run(ctx, cmdPools); ok {
		out.Pools = lines(n, nameLine)
	}
	if len(out.Errors) > 32 {
		out.Errors = out.Errors[:32]
	}
	return out, nil
}

// KVMSnapshot — снимок платформы C57 из собранного хоста KVM (без tenant/source/generation — их ставит collector).
func KVMSnapshot(h *KVMHost, instance string, target *string, at time.Time) contracts.PlatformSnapshot {
	name := h.Hostname
	if name == "" {
		name = instance
	}
	host := map[string]any{"hypervisor": "kvm"}
	for k, v := range h.Node {
		host[k] = v
	}
	if h.Version != "" {
		host["version"] = h.Version
	}
	hn := strings.ToLower(h.Hostname)
	s := contracts.PlatformSnapshot{Major: 1, Target: target, Platform: "kvm", Instance: instance, InstanceName: name, CollectedAt: at.UTC(), Complete: true, Errors: h.Errors,
		Objects:   []contracts.PlatformObject{{Ref: "host", Kind: "host", Name: name, Hostname: &hn, MACs: []string{}, Attrs: host}},
		Relations: []contracts.PlatformRelation{}}
	if len(h.Errors) > 0 {
		s.Complete = false // неполный сбор не должен помечать ВМ удалёнными
	}
	seen := map[string]bool{}
	for _, n := range h.Networks {
		ref := "net:" + n
		seen[ref] = true
		s.Objects = append(s.Objects, contracts.PlatformObject{Ref: ref, Kind: "network", Name: n, MACs: []string{}, Attrs: map[string]any{}})
		s.Relations = append(s.Relations, contracts.PlatformRelation{From: ref, Type: "located_in", To: "host"})
	}
	for _, p := range h.Pools {
		ref := "pool:" + p
		seen[ref] = true
		s.Objects = append(s.Objects, contracts.PlatformObject{Ref: ref, Kind: "datastore", Name: p, MACs: []string{}, Attrs: map[string]any{}})
		s.Relations = append(s.Relations, contracts.PlatformRelation{From: ref, Type: "located_in", To: "host"})
	}
	for _, d := range h.Domains {
		uuid := d.UUID
		macs := d.MACs
		if len(macs) > 32 {
			macs = macs[:32]
		}
		attrs := map[string]any{"vcpu": d.VCPU, "memory_mb": d.MemoryMB, "disks": d.Disks, "state": d.State}
		if d.OS != "" {
			attrs["machine"] = d.OS
		}
		ref := "vm:" + d.UUID
		s.Objects = append(s.Objects, contracts.PlatformObject{Ref: ref, Kind: "vm", Name: d.Name, BiosUUID: &uuid, MACs: macs, Attrs: attrs})
		s.Relations = append(s.Relations, contracts.PlatformRelation{From: ref, Type: "runs_on", To: "host"})
		for _, n := range unique(d.Networks) {
			if seen["net:"+n] {
				s.Relations = append(s.Relations, contracts.PlatformRelation{From: ref, Type: "connected_to", To: "net:" + n})
			}
		}
		for _, p := range unique(d.Pools) {
			if seen["pool:"+p] {
				s.Relations = append(s.Relations, contracts.PlatformRelation{From: ref, Type: "uses_storage", To: "pool:" + p})
			}
		}
	}
	return s
}

func unique(in []string) []string {
	m := map[string]bool{}
	out := []string{}
	for _, v := range in {
		if !m[v] {
			m[v] = true
			out = append(out, v)
		}
	}
	return out
}
