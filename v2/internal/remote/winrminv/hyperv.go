package winrminv

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
)

// C57.02 — Hyper-V по WinRM: только чтение CIM root\virtualization\v2 (ВМ, BIOS GUID, vCPU, память, MAC, коммутаторы).
// Нет роли Hyper-V или прав — ErrNoHyperV, цель продолжает обычный сбор. BIOS GUID ВМ = SMBIOS UUID гостя.

var ErrNoHyperV = errors.New("winrm: hyper-v is not available")

const HyperVScript = `$ErrorActionPreference='Stop'
try { $vms = @(Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem -Filter "Caption='Virtual Machine'") } catch { '{"hyperv":false}'; return }
$set = @{}; foreach ($s in @(Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_VirtualSystemSettingData -Filter "VirtualSystemType='Microsoft:Hyper-V:System:Realized'")) { $set[$s.VirtualSystemIdentifier] = $s }
$cpu = @{}; foreach ($p in @(Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ProcessorSettingData)) { if ($p.InstanceID -match 'Microsoft:([0-9A-Fa-f-]{36})') { $cpu[$matches[1]] = $p.VirtualQuantity } }
$mem = @{}; foreach ($m in @(Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_MemorySettingData)) { if ($m.InstanceID -match 'Microsoft:([0-9A-Fa-f-]{36})') { $mem[$matches[1]] = $m.VirtualQuantity } }
$mac = @{}; foreach ($n in @(Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_SyntheticEthernetPortSettingData)) { if ($n.InstanceID -match 'Microsoft:([0-9A-Fa-f-]{36})') { $mac[$matches[1]] = @($mac[$matches[1]]) + @($n.Address) } }
$sw = @(Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_VirtualEthernetSwitch | ForEach-Object { $_.ElementName })
$cs = Get-CimInstance Win32_ComputerSystem; $os = Get-CimInstance Win32_OperatingSystem
$out = @{ hyperv = $true; host = @{ name = $env:COMPUTERNAME; domain = $cs.Domain; cpus = $cs.NumberOfLogicalProcessors; memory_mb = [int]($cs.TotalPhysicalMemory/1MB); os = $os.Caption; version = $os.Version }; switches = $sw; vms = @() }
foreach ($v in $vms) { $id = $v.Name; $s = $set[$id]
  $out.vms += @{ id = $id; name = $v.ElementName; state = [int]$v.EnabledState; bios_guid = $(if ($s) { $s.BIOSGUID } else { $null }); vcpu = $cpu[$id]; memory_mb = $mem[$id]; macs = @($mac[$id] | Where-Object { $_ }) } }
$out | ConvertTo-Json -Depth 4 -Compress`

type HyperVVM struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	State    int      `json:"state"`
	BiosGUID *string  `json:"bios_guid"`
	VCPU     int      `json:"vcpu"`
	MemoryMB int      `json:"memory_mb"`
	MACs     []string `json:"macs"`
}

type HyperVHost struct {
	HyperV bool `json:"hyperv"`
	Host   struct {
		Name     string `json:"name"`
		Domain   string `json:"domain"`
		CPUs     int    `json:"cpus"`
		MemoryMB int    `json:"memory_mb"`
		OS       string `json:"os"`
		Version  string `json:"version"`
	} `json:"host"`
	Switches []string   `json:"switches"`
	VMs      []HyperVVM `json:"vms"`
}

var guid = regexp.MustCompile(`^\{?([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}?$`)

// ParseHyperV разбирает вывод HyperVScript (ConvertTo-Json даёт объект вместо массива при одном элементе — учтено).
func ParseHyperV(raw string) (*HyperVHost, error) {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "\xef\xbb\xbf"))
	var probe map[string]json.RawMessage
	if e := json.Unmarshal([]byte(raw), &probe); e != nil {
		return nil, errors.New("winrm: unexpected hyper-v output")
	}
	var on bool
	if e := json.Unmarshal(probe["hyperv"], &on); e != nil || !on {
		return nil, ErrNoHyperV
	}
	for _, k := range []string{"vms", "switches"} {
		if v := strings.TrimSpace(string(probe[k])); strings.HasPrefix(v, "{") || strings.HasPrefix(v, "\"") {
			probe[k] = json.RawMessage("[" + v + "]")
		} else if v == "" || v == "null" {
			probe[k] = json.RawMessage("[]")
		}
	}
	fixed, _ := json.Marshal(probe)
	var h HyperVHost
	if e := json.Unmarshal(fixed, &h); e != nil {
		return nil, errors.New("winrm: unexpected hyper-v output")
	}
	return &h, nil
}

// CollectHyperV выполняет HyperVScript на цели.
func CollectHyperV(ctx context.Context, run Runner) (*HyperVHost, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	out, err := run.RunPowerShell(ctx, HyperVScript, 16<<20)
	if err != nil {
		return nil, err
	}
	return ParseHyperV(out)
}

var hvState = map[int]string{2: "running", 3: "off", 6: "saved", 9: "paused", 32768: "paused", 32769: "saved"}

func macColon(m string) string {
	m = strings.ToLower(strings.NewReplacer("-", "", ":", "").Replace(m))
	if len(m) != 12 {
		return ""
	}
	return m[0:2] + ":" + m[2:4] + ":" + m[4:6] + ":" + m[6:8] + ":" + m[8:10] + ":" + m[10:12]
}

// HyperVSnapshot — снимок платформы C57 (без tenant/source/generation — их ставит collector).
func HyperVSnapshot(h *HyperVHost, instance string, target *string, at time.Time) contracts.PlatformSnapshot {
	name := h.Host.Name
	if name == "" {
		name = instance
	}
	fqdn := strings.ToLower(h.Host.Name)
	if h.Host.Domain != "" && fqdn != "" {
		fqdn += "." + strings.ToLower(h.Host.Domain)
	}
	s := contracts.PlatformSnapshot{Major: 1, Target: target, Platform: "hyperv", Instance: instance, InstanceName: name, CollectedAt: at.UTC(), Complete: true, Errors: []string{},
		Objects: []contracts.PlatformObject{{Ref: "host", Kind: "host", Name: name, Hostname: &fqdn, MACs: []string{},
			Attrs: map[string]any{"hypervisor": "hyperv", "cpus": h.Host.CPUs, "memory_mb": h.Host.MemoryMB, "os": h.Host.OS, "version": h.Host.Version}}},
		Relations: []contracts.PlatformRelation{}}
	for _, sw := range h.Switches {
		if sw == "" || len(sw) > 200 {
			continue
		}
		s.Objects = append(s.Objects, contracts.PlatformObject{Ref: "switch:" + sw, Kind: "network", Name: sw, MACs: []string{}, Attrs: map[string]any{}})
		s.Relations = append(s.Relations, contracts.PlatformRelation{From: "switch:" + sw, Type: "located_in", To: "host"})
	}
	if len(h.VMs) > 5000 {
		h.VMs, s.Complete, s.Errors = h.VMs[:5000], false, []string{"vms:truncated"}
	}
	for _, v := range h.VMs {
		m := guid.FindStringSubmatch(strings.TrimSpace(v.ID))
		if m == nil {
			continue
		}
		ref := "vm:" + strings.ToLower(m[1])
		var bios *string
		if v.BiosGUID != nil {
			if g := guid.FindStringSubmatch(strings.TrimSpace(*v.BiosGUID)); g != nil {
				b := strings.ToLower(g[1])
				bios = &b
			}
		}
		macs := []string{}
		for _, a := range v.MACs {
			if c := macColon(a); c != "" && len(macs) < 32 {
				macs = append(macs, c)
			}
		}
		state := hvState[v.State]
		if state == "" {
			state = "other"
		}
		n := v.Name
		if len(n) > 256 {
			n = n[:256]
		}
		s.Objects = append(s.Objects, contracts.PlatformObject{Ref: ref, Kind: "vm", Name: n, BiosUUID: bios, MACs: macs, Attrs: map[string]any{"vcpu": v.VCPU, "memory_mb": v.MemoryMB, "state": state}})
		s.Relations = append(s.Relations, contracts.PlatformRelation{From: ref, Type: "runs_on", To: "host"})
	}
	return s
}
