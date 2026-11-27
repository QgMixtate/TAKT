package ovirt

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/remote/tlspin"
)

// Синтетические ответы engine в формате REST API v4 (JSON): числа строками, ссылки {"href","id"}. Живого
// engine в CI нет; проверка на zVirt стенда — отдельным заданием.
var fixtures = map[string]string{
	"/ovirt-engine/api":             `{"product_info":{"name":"zVirt","vendor":"Orionsoft","version":{"build":"1","full_version":"4.2.1","major":"4","minor":"2"}}}`,
	"/ovirt-engine/api/datacenters": `{"data_center":[{"href":"/ovirt-engine/api/datacenters/dc1","id":"dc1","name":"Default","status":"up"}]}`,
	"/ovirt-engine/api/clusters":    `{"cluster":[{"id":"cl1","name":"Cluster1","data_center":{"href":"/ovirt-engine/api/datacenters/dc1","id":"dc1"}}]}`,
	"/ovirt-engine/api/hosts": `{"host":[{"id":"h1","name":"kvm01","address":"kvm01.lab.local","status":"up","type":"rhel","cluster":{"id":"cl1"},
	  "hardware_information":{"uuid":"4C4C4544-0042-3110-8030-B4C04F4E3332","serial_number":"ABC123","manufacturer":"Dell Inc.","product_name":"PowerEdge R640"},
	  "cpu":{"name":"Intel Xeon","topology":{"sockets":"2","cores":"8","threads":"2"}},"memory":"68719476736","os":{"type":"RHEL","version":{"full_version":"8.6"}},"version":{"full_version":"4.5"}},
	  {"id":"h2","name":"10.0.0.12","address":"10.0.0.12","status":"maintenance","cluster":{"id":"cl1"},"hardware_information":{},"cpu":{"topology":{}},"memory":"0"}]}`,
	"/ovirt-engine/api/vms": `{"vm":[{"id":"6f1d1c7e-1a2b-4c3d-9e8f-0a1b2c3d4e5f","name":"web01","status":"up","fqdn":"WEB01.lab.local","cluster":{"id":"cl1"},"host":{"id":"h1"},
	  "memory":"4294967296","cpu":{"topology":{"sockets":"2","cores":"1","threads":"1"}},"os":{"type":"rhel_8x64"},"guest_operating_system":{"distribution":"Astra Linux","version":{"full_version":"1.7"}},
	  "nics":{"nic":[{"mac":{"address":"56:6F:1A:00:00:01"}}]}},
	  {"id":"7a2e2d8f-2b3c-4d4e-8f90-1b2c3d4e5f60","name":"db01","status":"down","cluster":{"id":"cl1"},"memory":"1073741824","cpu":{"topology":{"sockets":"1","cores":"1","threads":"1"}},"os":{"type":"other"},"nics":{"nic":[]}}]}`,
	"/ovirt-engine/api/storagedomains": `{"storage_domain":[{"id":"sd1","name":"data1","type":"data","available":"107374182400","used":"53687091200","storage":{"type":"nfs"},"data_centers":{"data_center":[{"id":"dc1"}]}}]}`,
	"/ovirt-engine/api/networks":       `{"network":[{"id":"n1","name":"ovirtmgmt","data_center":{"id":"dc1"}},{"id":"n2","name":"vlan100","data_center":{"id":"dc1"},"vlan":{"id":"100"}}]}`,
}

func engine(t *testing.T, failVMs bool) (*httptest.Server, string, int) {
	t.Helper()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Version") != "4" || r.Header.Get("Accept") != "application/json" {
			http.Error(w, "read-only GET expected", 400)
			return
		}
		if u, p, ok := r.BasicAuth(); !ok || u != "ro-takt@internal" || p != "secret-57" {
			http.Error(w, "auth", 401)
			return
		}
		if r.URL.Path == "/ovirt-engine/api/vms" && (r.URL.Query().Get("follow") != "nics" || failVMs) {
			http.Error(w, "boom", 500)
			return
		}
		body, ok := fixtures[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	host, port, _ := strings.Cut(s.Listener.Addr().String(), ":")
	n, _ := strconv.Atoi(port)
	return s, host, n
}

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
	sch, err := c.Compile("urn:c57#/$defs/PlatformSnapshot")
	if err != nil {
		t.Fatal(err)
	}
	inst, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
	if err = sch.Validate(inst); err != nil {
		t.Fatalf("snapshot violates c57: %v", err)
	}
}

func TestCollectAndSnapshot(t *testing.T) {
	s, host, port := engine(t, false)
	defer s.Close()
	pin := tlspin.SHA256(s.Certificate().Raw)
	ctx := context.Background()
	base := Target{Host: host, Port: port, User: "ro-takt@internal", Password: []byte("secret-57"), Timeout: 20 * time.Second}
	if _, err := Collect(ctx, base); !errors.Is(err, ErrPolicy) {
		t.Fatal("verification must be required", err)
	}
	good := base
	good.CertSHA256 = pin
	inv, err := Collect(ctx, good)
	if err != nil {
		t.Fatal(err)
	}
	id := identifier.New()
	snap := Snapshot(inv, "engine.lab.local", &id, time.Now())
	if !snap.Complete || snap.Platform != "ovirt" || snap.Instance != "ovirt:engine.lab.local" {
		t.Fatalf("head %+v", snap.Instance)
	}
	byRef := map[string]int{}
	for i, o := range snap.Objects {
		byRef[o.Ref] = i
	}
	h := snap.Objects[byRef["host:h1"]]
	if h.BiosUUID == nil || *h.BiosUUID != "4c4c4544-0042-3110-8030-b4c04f4e3332" || h.Serial == nil || *h.Serial != "ABC123" || h.Hostname == nil || *h.Hostname != "kvm01.lab.local" ||
		h.Attrs["memory_mb"] != int64(65536) || h.Attrs["cpu_cores"] != int64(16) {
		t.Fatalf("host %+v", h)
	}
	if h2 := snap.Objects[byRef["host:h2"]]; h2.Hostname != nil || h2.BiosUUID != nil {
		t.Fatalf("host by IP must have no hostname/uuid %+v", h2)
	}
	vm := snap.Objects[byRef["vm:6f1d1c7e-1a2b-4c3d-9e8f-0a1b2c3d4e5f"]]
	if vm.BiosUUID == nil || *vm.BiosUUID != "6f1d1c7e-1a2b-4c3d-9e8f-0a1b2c3d4e5f" || len(vm.MACs) != 1 || vm.MACs[0] != "56:6f:1a:00:00:01" || vm.Attrs["state"] != "running" ||
		vm.Attrs["memory_mb"] != int64(4096) || *vm.Hostname != "web01.lab.local" || vm.Attrs["guest_os"] != "Astra Linux 1.7" {
		t.Fatalf("vm %+v", vm)
	}
	rel := map[string]bool{}
	for _, r := range snap.Relations {
		rel[r.From+" "+r.Type+" "+r.To] = true
	}
	for _, want := range []string{"vm:6f1d1c7e-1a2b-4c3d-9e8f-0a1b2c3d4e5f runs_on host:h1", "host:h1 member_of cluster:cl1", "host:h1 located_in datacenter:dc1",
		"cluster:cl1 located_in datacenter:dc1", "datastore:sd1 located_in datacenter:dc1", "network:n2 located_in datacenter:dc1"} {
		if !rel[want] {
			t.Fatalf("relation %q missing: %v", want, rel)
		}
	}
	if rel["vm:7a2e2d8f-2b3c-4d4e-8f90-1b2c3d4e5f60 runs_on host:h1"] {
		t.Fatal("stopped VM has no host")
	}
	snap.Tenant, snap.Source, snap.Generation, snap.SnapshotID = identifier.New(), identifier.New(), identifier.New(), identifier.New()
	raw, _ := json.Marshal(snap)
	validSnapshot(t, raw)

	bad := good
	bad.Password = []byte("wrong")
	if _, err = Collect(ctx, bad); !errors.Is(err, ErrAuth) {
		t.Fatal("bad password must be auth_failed", err)
	}
	other := base
	other.CertSHA256 = strings.Repeat("0", 64)
	if _, err = Collect(ctx, other); !errors.Is(err, ErrCertChanged) {
		t.Fatal("changed certificate must be reported", err)
	}
}

func TestPartialSnapshotWhenSectionFails(t *testing.T) {
	s, host, port := engine(t, true)
	defer s.Close()
	inv, err := Collect(context.Background(), Target{Host: host, Port: port, User: "ro-takt@internal", Password: []byte("secret-57"), CertSHA256: tlspin.SHA256(s.Certificate().Raw), Timeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	snap := Snapshot(inv, "engine", nil, time.Now())
	if snap.Complete || len(snap.Errors) != 1 || snap.Errors[0] != "vms:unavailable" {
		t.Fatalf("partial snapshot must be incomplete: %v %v", snap.Complete, snap.Errors)
	}
}

func TestNotEngine(t *testing.T) {
	s := httptest.NewTLSServer(http.NotFoundHandler())
	defer s.Close()
	host, port, _ := strings.Cut(s.Listener.Addr().String(), ":")
	n, _ := strconv.Atoi(port)
	if _, err := Collect(context.Background(), Target{Host: host, Port: n, User: "u", Password: []byte("p"), CertSHA256: tlspin.SHA256(s.Certificate().Raw)}); !errors.Is(err, ErrNotOVirt) {
		t.Fatal("not an engine", err)
	}
}
