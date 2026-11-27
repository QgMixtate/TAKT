package vsphere

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vmware/govmomi/simulator"
	"github.com/vmware/govmomi/vim25"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// Проверка на официальном симуляторе vSphere (vcsim из govmomi): живого vCenter в CI нет.

func validSnapshot(t *testing.T, raw []byte) {
	t.Helper()
	doc, err := os.ReadFile("../../../contracts/c57-platform.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	d, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(doc)))
	if err = c.AddResource("urn:c57", d); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("urn:c57#/$defs/PlatformSnapshot")
	if err != nil {
		t.Fatal(err)
	}
	inst, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
	if err = s.Validate(inst); err != nil {
		t.Fatalf("snapshot violates c57: %v", err)
	}
}

func TestSnapshotFromVCSim(t *testing.T) {
	m := simulator.VPX()
	m.Datacenter, m.Cluster, m.ClusterHost, m.Host, m.Machine = 2, 1, 2, 1, 2
	defer m.Remove()
	if err := m.Create(); err != nil {
		t.Fatal(err)
	}
	err := m.Run(func(ctx context.Context, c *vim25.Client) error {
		inv, err := read(ctx, c)
		if err != nil {
			return err
		}
		if len(inv.Errors) != 0 {
			t.Fatalf("errors: %v", inv.Errors)
		}
		id := identifier.New()
		s := Snapshot(inv, "vc.example", &id, time.Now())
		if !s.Complete || s.Platform != "vsphere" || !strings.HasPrefix(s.Instance, "vsphere:") {
			t.Fatalf("snapshot head: %+v", s.Instance)
		}
		count := map[string]int{}
		bios := 0
		refs := map[string]string{}
		for _, o := range s.Objects {
			count[o.Kind]++
			refs[o.Ref] = o.Kind
			if o.Kind == "vm" && o.BiosUUID != nil {
				bios++
			}
		}
		// 2 ЦОД × (1 кластер × 2 хоста + 1 отдельный хост); ВМ — по 2 на кластер и на отдельный хост
		if count["datacenter"] != 2 || count["cluster"] != 2 || count["host"] != 6 || count["vm"] != 8 || count["datastore"] == 0 || count["network"] == 0 {
			t.Fatalf("objects: %v", count)
		}
		if bios != count["vm"] {
			t.Fatal("every VM must carry BIOS UUID for matching")
		}
		rel := map[string]int{}
		for _, r := range s.Relations {
			rel[refs[r.From]+" "+r.Type+" "+refs[r.To]]++
		}
		if rel["vm runs_on host"] != 8 || rel["host member_of cluster"] != 4 || rel["host located_in datacenter"] != 6 || rel["vm uses_storage datastore"] == 0 {
			t.Fatalf("relations: %v", rel)
		}
		s.Tenant, s.Source, s.Generation, s.SnapshotID = identifier.New(), identifier.New(), identifier.New(), identifier.New()
		raw, _ := json.Marshal(s)
		validSnapshot(t, raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCollectPinnedCertificate(t *testing.T) {
	m := simulator.ESX()
	defer m.Remove()
	if err := m.Create(); err != nil {
		t.Fatal(err)
	}
	m.Service.TLS = new(tls.Config)
	m.Service.Listen = &url.URL{User: url.UserPassword("ro", "secret-ro")}
	s := m.Service.NewServer()
	defer s.Close()
	host, portText, _ := strings.Cut(s.URL.Host, ":")
	port, _ := strconv.Atoi(portText)
	user := s.URL.User.Username()
	pass, _ := s.URL.User.Password()
	pin, err := FetchCert(host, port, "", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// без способа проверки — отказ до подключения
	if _, err = Collect(ctx, Target{Host: host, Port: port, User: user, Password: []byte(pass)}); !errors.Is(err, ErrPolicy) {
		t.Fatal("verification must be required", err)
	}
	inv, err := Collect(ctx, Target{Host: host, Port: port, User: user, Password: []byte(pass), CertSHA256: pin, Timeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	snap := Snapshot(inv, s.URL.Host, nil, time.Now())
	hosts := 0
	for _, o := range snap.Objects {
		if o.Kind == "host" {
			hosts++
		}
	}
	if hosts != 1 || inv.About.ApiType != "HostAgent" {
		t.Fatalf("esx: hosts=%d api=%s", hosts, inv.About.ApiType)
	}
	// другой отпечаток — сертификат сменился, пароль не отправляется
	other := strings.Repeat("0", 64)
	if _, err = Collect(ctx, Target{Host: host, Port: port, User: user, Password: []byte(pass), CertSHA256: other, Timeout: 30 * time.Second}); !errors.Is(err, ErrCertChanged) {
		t.Fatal("changed certificate must be reported", err)
	}
	// неверный пароль — вход отклонён
	if _, err = Collect(ctx, Target{Host: host, Port: port, User: user, Password: []byte("wrong"), CertSHA256: pin, Timeout: 30 * time.Second}); !errors.Is(err, ErrAuth) {
		t.Fatal("bad password must be auth_failed", err)
	}
}
