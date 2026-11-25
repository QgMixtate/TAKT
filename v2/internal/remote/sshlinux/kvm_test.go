package sshlinux

import (
	"context"
	"testing"
	"time"
)

const domainSample = `<domain type='kvm' id='3'>
  <name>web-01</name>
  <uuid>4C4C4544-0042-3110-8030-B4C04F4E3332</uuid>
  <memory unit='KiB'>4194304</memory>
  <vcpu placement='static'>2</vcpu>
  <os><type arch='x86_64' machine='pc-q35-8.2'>hvm</type></os>
  <devices>
    <disk type='volume' device='disk'><source pool='default' volume='web-01.qcow2'/></disk>
    <disk type='file' device='cdrom'><source file='/iso/ubuntu.iso'/></disk>
    <interface type='network'><mac address='52:54:00:AB:CD:01'/><source network='default'/></interface>
    <interface type='bridge'><mac address='52:54:00:ab:cd:02'/><source bridge='br0'/></interface>
  </devices>
</domain>`

func TestParseDomainXML(t *testing.T) {
	d, e := ParseDomainXML(domainSample)
	if e != nil || d.UUID != "4c4c4544-0042-3110-8030-b4c04f4e3332" || d.Name != "web-01" || d.VCPU != 2 || d.MemoryMB != 4096 || d.Disks != 1 ||
		len(d.MACs) != 2 || d.MACs[0] != "52:54:00:ab:cd:01" || len(d.Networks) != 1 || d.Networks[0] != "default" || len(d.Bridges) != 1 || len(d.Pools) != 1 || d.OS != "hvm x86_64" {
		t.Fatalf("parsed %+v %v", d, e)
	}
	if _, e = ParseDomainXML(`<domain><name>x</name><uuid>not-uuid</uuid></domain>`); e == nil {
		t.Fatal("invalid uuid accepted")
	}
	if _, e = ParseDomainXML(`<!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]><domain><uuid>&x;</uuid></domain>`); e == nil {
		t.Fatal("external entity must not resolve")
	}
}

func TestParseNodeInfoAndSnapshot(t *testing.T) {
	n := ParseNodeInfo("CPU model:           x86_64\nCPU(s):              16\nCPU socket(s):       1\nMemory size:         65842288 KiB\n")
	if n["cpus"] != 16 || n["memory_mb"] != 64299 || n["cpu_arch"] != "x86_64" {
		t.Fatalf("nodeinfo %v", n)
	}
	d, _ := ParseDomainXML(domainSample)
	h := &KVMHost{Hostname: "kvm01", Version: "QEMU 8.2.2", Node: n, Domains: []KVMDomain{d}, Networks: []string{"default"}, Pools: []string{"default"}, Errors: []string{}}
	s := KVMSnapshot(h, "10.0.0.5:22", nil, time.Now())
	if !s.Complete || len(s.Objects) != 4 || len(s.Relations) != 5 || s.Objects[3].BiosUUID == nil || *s.Objects[3].BiosUUID != d.UUID {
		t.Fatalf("snapshot %+v", s)
	}
	h.Errors = []string{"dumpxml:unavailable"}
	if KVMSnapshot(h, "x", nil, time.Now()).Complete {
		t.Fatal("partial collection must not be a complete snapshot")
	}
}

func TestCollectKVMOverSSHReadonlyOnly(t *testing.T) {
	u := "4c4c4544-0042-3110-8030-b4c04f4e3332"
	out := map[string]string{
		cmdVirshVer:             "Compiled against library: libvirt 10.0.0\nUsing library: libvirt 10.0.0\nUsing API: QEMU 10.0.0\nRunning hypervisor: QEMU 8.2.2\n",
		cmdHostname:             "kvm01\n",
		cmdNodeInfo:             "CPU model:           x86_64\nCPU(s):              8\nMemory size:         16384000 KiB\n",
		cmdListUUIDs:            u + "\n\n",
		virsh + "dumpxml " + u:  domainSample,
		virsh + "domstate " + u: "running\n\n",
		cmdNets:                 "default\n",
		cmdPools:                "default\n",
	}
	s := startServer(t, "pw", out)
	h, err := CollectKVM(context.Background(), Target{Addr: s.addr, User: "scan", HostKeySHA256: s.hostFP}, Secret{Password: "pw"}, Policy{})
	if err != nil || h.Hostname != "kvm01" || h.Version != "QEMU 8.2.2" || len(h.Domains) != 1 || h.Domains[0].State != "running" || len(h.Errors) != 0 {
		t.Fatalf("kvm %+v %v", h, err)
	}
	// без libvirt — ErrNoLibvirt, а не ошибка цели
	s2 := startServer(t, "pw", map[string]string{cmdHostname: "plain\n"})
	if _, err = CollectKVM(context.Background(), Target{Addr: s2.addr, User: "scan", HostKeySHA256: s2.hostFP}, Secret{Password: "pw"}, Policy{}); err != ErrNoLibvirt {
		t.Fatalf("no libvirt: %v", err)
	}
}
