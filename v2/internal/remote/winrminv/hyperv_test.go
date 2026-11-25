package winrminv

import (
	"testing"
	"time"
)

func TestParseHyperVSingleAndSnapshot(t *testing.T) {
	// один ВМ и один коммутатор: ConvertTo-Json отдаёт объекты, а не массивы
	raw := "\xef\xbb\xbf" + `{"hyperv":true,"host":{"name":"HV01","domain":"corp.local","cpus":16,"memory_mb":65536,"os":"Windows Server 2022","version":"10.0.20348"},"switches":"vSwitch-LAN",` +
		`"vms":{"id":"6B1F3C2A-1111-4222-8333-444455556666","name":"app01","state":2,"bios_guid":"{0C1D2E3F-AAAA-4BBB-8CCC-DDDDEEEEFFFF}","vcpu":4,"memory_mb":8192,"macs":["00155D010203"]}}`
	h, e := ParseHyperV(raw)
	if e != nil || len(h.VMs) != 1 || len(h.Switches) != 1 || h.Host.CPUs != 16 {
		t.Fatalf("parse %+v %v", h, e)
	}
	s := HyperVSnapshot(h, "winrm:10.0.0.10:5986", nil, time.Now())
	vm := s.Objects[2]
	if len(s.Objects) != 3 || vm.BiosUUID == nil || *vm.BiosUUID != "0c1d2e3f-aaaa-4bbb-8ccc-ddddeeeeffff" || vm.MACs[0] != "00:15:5d:01:02:03" || vm.Attrs["state"] != "running" ||
		*s.Objects[0].Hostname != "hv01.corp.local" || len(s.Relations) != 2 {
		t.Fatalf("snapshot %+v", s)
	}
	if _, e = ParseHyperV(`{"hyperv":false}`); e != ErrNoHyperV {
		t.Fatalf("no hyper-v: %v", e)
	}
	if _, e = ParseHyperV(`not json`); e == nil || e == ErrNoHyperV {
		t.Fatalf("garbage: %v", e)
	}
}
