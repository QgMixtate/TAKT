// Package ovirt — C57.03: коннектор oVirt / zVirt (REST API engine v4, JSON) только на чтение. Читаются ЦОД,
// кластеры, хосты, ВМ (с сетевыми картами), домены хранения и логические сети; итог — снимок платформы C57 «ovirt»,
// который collector подписывает и отправляет центру.
//
// Только чтение: только запросы GET к /ovirt-engine/api; вход — HTTP Basic на каждый запрос (учётка вида
// `ro-takt@internal` или доменная, роль ReadOnlyAdmin на уровне системы). Проверка сервера — tlspin (PEM CA или
// закреплённый отпечаток); HTTP-прокси окружения не используется.
package ovirt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/remote/tlspin"
)

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
	ErrPolicy      = tlspin.ErrPolicy
	ErrCertChanged = tlspin.ErrCertChanged
	// ErrAuth — вход отклонён (401/403).
	ErrAuth = errors.New("ovirt: login rejected (auth_failed)")
	// ErrNotOVirt — по адресу нет API engine.
	ErrNotOVirt = errors.New("ovirt: no engine API at address (not_ovirt)")
)

// FetchCert — сертификат engine без входа (для закрепления при первом подключении).
func FetchCert(host string, port int, serverName string, timeout time.Duration) (string, error) {
	if port == 0 {
		port = 443
	}
	return tlspin.Fetch(host, port, serverName, timeout)
}

// num — число, которое engine отдаёт то числом, то строкой ("memory": "4294967296").
type num int64

func (n *num) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*n = 0
		return nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil // не число — не важно для инвентаризации
	}
	*n = num(v)
	return nil
}

type ref struct {
	ID string `json:"id"`
}

type version struct {
	Full string `json:"full_version"`
}

type API struct {
	Product struct {
		Name    string  `json:"name"`
		Vendor  string  `json:"vendor"`
		Version version `json:"version"`
	} `json:"product_info"`
}

type DataCenter struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type Cluster struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	DataCenter *ref   `json:"data_center"`
}

type topology struct {
	Sockets num `json:"sockets"`
	Cores   num `json:"cores"`
	Threads num `json:"threads"`
}

type Host struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Status  string `json:"status"`
	Type    string `json:"type"`
	Cluster *ref   `json:"cluster"`
	HW      struct {
		UUID         string `json:"uuid"`
		Serial       string `json:"serial_number"`
		Manufacturer string `json:"manufacturer"`
		Product      string `json:"product_name"`
	} `json:"hardware_information"`
	CPU struct {
		Name     string   `json:"name"`
		Topology topology `json:"topology"`
	} `json:"cpu"`
	Memory num `json:"memory"`
	OS     struct {
		Type    string  `json:"type"`
		Version version `json:"version"`
	} `json:"os"`
	Version version `json:"version"`
}

type VM struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	FQDN    string `json:"fqdn"`
	Cluster *ref   `json:"cluster"`
	Host    *ref   `json:"host"`
	Memory  num    `json:"memory"`
	CPU     struct {
		Topology topology `json:"topology"`
	} `json:"cpu"`
	OS struct {
		Type string `json:"type"`
	} `json:"os"`
	Guest struct {
		Distribution string  `json:"distribution"`
		Version      version `json:"version"`
	} `json:"guest_operating_system"`
	NICs struct {
		NIC []struct {
			MAC struct {
				Address string `json:"address"`
			} `json:"mac"`
		} `json:"nic"`
	} `json:"nics"`
}

type StorageDomain struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Available num    `json:"available"`
	Used      num    `json:"used"`
	Storage   struct {
		Type string `json:"type"`
	} `json:"storage"`
	DataCenters struct {
		DataCenter []ref `json:"data_center"`
	} `json:"data_centers"`
}

type Network struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	DataCenter *ref   `json:"data_center"`
	VLAN       *struct {
		ID num `json:"id"`
	} `json:"vlan"`
}

// Inventory — прочитанное из engine (без секретов).
type Inventory struct {
	API         API
	DataCenters []DataCenter
	Clusters    []Cluster
	Hosts       []Host
	VMs         []VM
	Storage     []StorageDomain
	Networks    []Network
	Errors      []string
}

type client struct {
	http *http.Client
	base string
	user string
	pass string
}

const maxBody = 64 << 20

func (c *client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.user, c.pass)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Version", "4")
	resp, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, tlspin.ErrCertChanged) || strings.Contains(err.Error(), "cert_changed") {
			return ErrCertChanged
		}
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		return ErrAuth
	case resp.StatusCode == 404:
		return ErrNotOVirt
	case resp.StatusCode != 200:
		return fmt.Errorf("ovirt: http %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return err
	}
	if len(b) > maxBody {
		return errors.New("ovirt: response too large")
	}
	if json.Unmarshal(b, out) != nil {
		return ErrNotOVirt
	}
	return nil
}

// Collect читает engine. Ошибка корня API (адрес, вход, сертификат) — ошибка; ошибка отдельного раздела — код в
// Inventory.Errors (снимок неполный, объекты не помечаются удалёнными).
func Collect(ctx context.Context, t Target) (*Inventory, error) {
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cfg, err := tlspin.Config(t.CAPEM, t.ServerName, t.Host, t.CertSHA256)
	if err != nil {
		return nil, err
	}
	port := t.Port
	if port == 0 {
		port = 443
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: cfg, DialContext: (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
		TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 2 * time.Minute, MaxIdleConns: 2}
	defer tr.CloseIdleConnections()
	c := &client{http: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		base: (&url.URL{Scheme: "https", Host: net.JoinHostPort(t.Host, strconv.Itoa(port)), Path: "/ovirt-engine/api"}).String(),
		user: t.User, pass: string(t.Password)}
	inv := &Inventory{Errors: []string{}}
	if err = c.get(ctx, "", &inv.API); err != nil {
		return nil, err
	}
	if inv.API.Product.Name == "" {
		return nil, ErrNotOVirt
	}
	part := func(code, path string, out any) {
		if e := c.get(ctx, path, out); e != nil {
			inv.Errors = append(inv.Errors, code+":unavailable")
		}
	}
	var dcs struct {
		Items []DataCenter `json:"data_center"`
	}
	var clusters struct {
		Items []Cluster `json:"cluster"`
	}
	var hosts struct {
		Items []Host `json:"host"`
	}
	var vms struct {
		Items []VM `json:"vm"`
	}
	var sds struct {
		Items []StorageDomain `json:"storage_domain"`
	}
	var nets struct {
		Items []Network `json:"network"`
	}
	part("datacenters", "/datacenters", &dcs)
	part("clusters", "/clusters", &clusters)
	part("hosts", "/hosts", &hosts)
	part("vms", "/vms?follow=nics", &vms)
	part("storagedomains", "/storagedomains", &sds)
	part("networks", "/networks", &nets)
	inv.DataCenters, inv.Clusters, inv.Hosts, inv.VMs, inv.Storage, inv.Networks = dcs.Items, clusters.Items, hosts.Items, vms.Items, sds.Items, nets.Items
	return inv, nil
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

func lowerUUID(s string) *string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != 36 || strings.Count(s, "-") != 4 || s == "00000000-0000-0000-0000-000000000000" {
		return nil
	}
	return &s
}

func macNorm(m string) string {
	m = strings.ToLower(strings.NewReplacer("-", "", ":", "").Replace(strings.TrimSpace(m)))
	if len(m) != 12 {
		return ""
	}
	return m[0:2] + ":" + m[2:4] + ":" + m[4:6] + ":" + m[6:8] + ":" + m[8:10] + ":" + m[10:12]
}

func vmState(s string) string {
	switch s {
	case "up", "powering_up", "reboot_in_progress", "migrating":
		return "running"
	case "down", "powering_down":
		return "off"
	case "suspended", "saving_state", "restoring_state":
		return "saved"
	case "paused":
		return "paused"
	}
	return "other"
}

const (
	maxObjects   = 20000
	maxRelations = 50000
)

// Snapshot — снимок платформы C57 «ovirt» (без tenant/source/generation — их ставит collector).
func Snapshot(inv *Inventory, address string, target *string, at time.Time) contracts.PlatformSnapshot {
	s := contracts.PlatformSnapshot{Major: 1, Target: target, Platform: "ovirt", Instance: cut("ovirt:"+address, 256), InstanceName: cut(address, 256),
		CollectedAt: at.UTC(), Complete: len(inv.Errors) == 0, Objects: []contracts.PlatformObject{}, Relations: []contracts.PlatformRelation{},
		Errors: append([]string{}, inv.Errors...)}
	seen := map[string]bool{}
	truncated := false
	add := func(o contracts.PlatformObject) bool {
		if o.Ref == "" || seen[o.Ref] {
			return seen[o.Ref]
		}
		if len(s.Objects) >= maxObjects {
			truncated = true
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
			truncated = true
			return
		}
		rels[r] = true
		s.Relations = append(s.Relations, r)
	}
	id := func(kind, v string) string {
		if v == "" || len(v) > 128 {
			return ""
		}
		return kind + ":" + v
	}
	product := cut(strings.TrimSpace(inv.API.Product.Name+" "+inv.API.Product.Version.Full), 256)
	clusterDC := map[string]string{}
	sort.Slice(inv.DataCenters, func(i, j int) bool { return inv.DataCenters[i].ID < inv.DataCenters[j].ID })
	for _, dc := range inv.DataCenters {
		add(contracts.PlatformObject{Ref: id("datacenter", dc.ID), Kind: "datacenter", Name: cut(dc.Name, 256), Attrs: map[string]any{"status": cut(dc.Status, 64), "product": product}})
	}
	for _, c := range inv.Clusters {
		r := id("cluster", c.ID)
		if !add(contracts.PlatformObject{Ref: r, Kind: "cluster", Name: cut(c.Name, 256)}) {
			continue
		}
		if c.DataCenter != nil {
			clusterDC[c.ID] = c.DataCenter.ID
			rel(r, "located_in", id("datacenter", c.DataCenter.ID))
		}
	}
	for _, sd := range inv.Storage {
		r := id("datastore", sd.ID)
		if !add(contracts.PlatformObject{Ref: r, Kind: "datastore", Name: cut(sd.Name, 256), Attrs: map[string]any{"type": cut(sd.Type, 64),
			"storage": cut(sd.Storage.Type, 64), "capacity_gb": int64(sd.Available+sd.Used) >> 30, "free_gb": int64(sd.Available) >> 30}}) {
			continue
		}
		for _, dc := range sd.DataCenters.DataCenter {
			rel(r, "located_in", id("datacenter", dc.ID))
		}
	}
	for _, n := range inv.Networks {
		r := id("network", n.ID)
		attrs := map[string]any{}
		if n.VLAN != nil {
			attrs["vlan"] = int64(n.VLAN.ID)
		}
		if !add(contracts.PlatformObject{Ref: r, Kind: "network", Name: cut(n.Name, 256), Attrs: attrs}) {
			continue
		}
		if n.DataCenter != nil {
			rel(r, "located_in", id("datacenter", n.DataCenter.ID))
		}
	}
	for _, h := range inv.Hosts {
		r := id("host", h.ID)
		hostname := optional(strings.ToLower(h.Address), 255)
		if hostname != nil && net.ParseIP(*hostname) != nil {
			hostname = nil
		}
		t := h.CPU.Topology
		attrs := map[string]any{"hypervisor": "kvm", "status": cut(h.Status, 64), "host_type": cut(h.Type, 64), "vendor": cut(h.HW.Manufacturer, 256),
			"model": cut(h.HW.Product, 256), "cpu_model": cut(h.CPU.Name, 256), "cpu_cores": int64(t.Sockets * t.Cores), "cpu_threads": int64(t.Sockets * t.Cores * max(t.Threads, 1)),
			"memory_mb": int64(h.Memory) >> 20, "os": cut(strings.TrimSpace(h.OS.Type+" "+h.OS.Version.Full), 256), "version": cut(h.Version.Full, 64)}
		if !add(contracts.PlatformObject{Ref: r, Kind: "host", Name: cut(h.Name, 256), BiosUUID: lowerUUID(h.HW.UUID), Serial: optional(h.HW.Serial, 128), Hostname: hostname, Attrs: attrs}) {
			continue
		}
		if h.Cluster != nil {
			rel(r, "member_of", id("cluster", h.Cluster.ID))
			if dc := clusterDC[h.Cluster.ID]; dc != "" {
				rel(r, "located_in", id("datacenter", dc))
			}
		}
	}
	for _, v := range inv.VMs {
		r := id("vm", v.ID)
		macs := []string{}
		for _, n := range v.NICs.NIC {
			if m := macNorm(n.MAC.Address); m != "" && len(macs) < 32 {
				macs = append(macs, m)
			}
		}
		t := v.CPU.Topology
		guest := strings.TrimSpace(v.Guest.Distribution + " " + v.Guest.Version.Full)
		if guest == "" {
			guest = v.OS.Type
		}
		attrs := map[string]any{"state": vmState(v.Status), "status": cut(v.Status, 64), "vcpu": int64(max(t.Sockets, 1) * max(t.Cores, 1) * max(t.Threads, 1)),
			"memory_mb": int64(v.Memory) >> 20, "guest_os": cut(guest, 256)}
		// SMBIOS UUID гостя в oVirt/zVirt — идентификатор ВМ
		if !add(contracts.PlatformObject{Ref: r, Kind: "vm", Name: cut(v.Name, 256), BiosUUID: lowerUUID(v.ID), Hostname: optional(strings.ToLower(v.FQDN), 255), MACs: macs, Attrs: attrs}) {
			continue
		}
		if v.Host != nil {
			rel(r, "runs_on", id("host", v.Host.ID))
		}
		if v.Cluster != nil {
			rel(r, "member_of", id("cluster", v.Cluster.ID))
		}
	}
	if truncated {
		s.Complete = false
		s.Errors = append(s.Errors, "objects:truncated")
	}
	if len(s.Errors) > 32 {
		s.Errors = s.Errors[:32]
	}
	return s
}
