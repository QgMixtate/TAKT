//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/health"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// C54.04: API РСМ через HTTP с сессией браузера — каждый ответ по контракту c54-rsm.schema.json: направление,
// поля системы с ревизией, среда, компонент с эталоном, правило → предложение после приёма наблюдения →
// подтверждение, массовая привязка, пересчёт состояния, обзор, список и дерево системы, компонент с хостами,
// «вне систем», РСМ в карточке хоста, основная/снятие привязки, снятие правила, проход правил, импорт (предпросмотр).
func TestC54RSMHTTP(t *testing.T) {
	f := registrySetup(t)
	ctx := f.ctx
	if _, err := f.registry.ConfigureInventoryProtocol12(true); err != nil {
		t.Fatal(err)
	}
	machine := &sources.MachineService{Pool: f.pool, Audit: audit.Store{}}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	source, generation := identifier.New(), identifier.New()
	if _, err := machine.RegisterPortable(ctx, "console", sources.PortableRegistration{Tenant: tenant, Site: siteID, Scope: scopeID, Source: source, Generation: generation, PublicKey: pub}); err != nil {
		t.Fatal(err)
	}
	seq := 0
	host := func(name string) string {
		seq++
		o := testObservation12(t, f, strconv.Itoa(seq))
		o.Origin = contracts.Origin{SourceID: source, SourceKind: "portable", GenerationID: generation}
		o.Record = contracts.SourceRecord{Namespace: "host", LocalID: "host:" + name}
		o.Clock = "estimated"
		o.Candidates = []contracts.Candidate{{Kind: "machine_uuid", Namespace: "linux-machine-id", Value: "4c4c4544-0000-1000-8000-" + identifier.New()[24:]}, {Kind: "hostname", Namespace: "hostname.raw", Value: name}}
		raw, _ := json.Marshal(o)
		report, err := f.registry.ImportPortable(ctx, machine, tenant, source, portablePackage(t, key, source, raw))
		if err != nil || len(report.Records) != 1 || report.Records[0].Disposition != "applied" {
			t.Fatal(err, report)
		}
		return report.Records[0].AssetID
	}
	schemaRaw, err := os.ReadFile("../../contracts/c54-rsm.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(schemaRaw)))
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err = compiler.AddResource("urn:surveyscan:c54:rsm:1:0", doc); err != nil {
		t.Fatal(err)
	}
	valid := func(def string, raw []byte) {
		t.Helper()
		schema, err := compiler.Compile("urn:surveyscan:c54:rsm:1:0#/$defs/" + def)
		if err != nil {
			t.Fatal(err)
		}
		instance, err := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
		if err != nil {
			t.Fatal(err)
		}
		if err = schema.Validate(instance); err != nil {
			t.Fatalf("%s violates contract: %v\n%s", def, err, raw)
		}
	}
	auth, err := access.NewHTTP(f.users, "https://ui.example", false)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := app.NewHTTP(auth, health.Handler(func(context.Context) error { return nil }), f.registry)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	b := newBrowser(t, server)
	session := b.login(t, "admin")
	get := func(path, def string) []byte {
		t.Helper()
		code, raw, _ := b.request(t, "GET", path, "", "", "", nil)
		if code != 200 {
			t.Fatalf("GET %s: %d %s", path, code, raw)
		}
		valid(def, raw)
		return raw
	}
	send := func(method, path, body string, want int, def string) []byte {
		t.Helper()
		code, raw, _ := b.request(t, method, path, body, session.CSRFToken, "https://ui.example", nil)
		if code != want {
			t.Fatalf("%s %s %s: want %d, got %d %s", method, path, body, want, code, raw)
		}
		if def != "" {
			valid(def, raw)
		}
		return raw
	}
	var service struct {
		UID      string `json:"service_uid"`
		Revision string `json:"revision"`
	}
	_ = json.Unmarshal(send("POST", "/api/v1/services", `{"name":"CRM","criticality":"high"}`, 201, ""), &service)
	var dir struct {
		UID string `json:"direction_uid"`
	}
	_ = json.Unmarshal(send("POST", "/api/v1/rsm/directions", `{"name":"Продажи"}`, 201, "DirectionCreated"), &dir)
	send("POST", "/api/v1/rsm/directions", `{"name":"продажи"}`, 409, "")
	send("PATCH", "/api/v1/rsm/systems/"+service.UID, `{"revision":"`+service.Revision+`","direction_uid":"`+dir.UID+`","business_owner":"Коммерческий департамент"}`, 200, "System")
	send("PATCH", "/api/v1/rsm/systems/"+service.UID, `{"revision":"`+service.Revision+`","business_owner":"x"}`, 412, "")
	var env struct {
		ID string `json:"environment_id"`
	}
	_ = json.Unmarshal(send("POST", "/api/v1/rsm/systems/"+service.UID+"/environments", `{"kind":"prod","name":"Прод"}`, 201, "Environment"), &env)
	send("POST", "/api/v1/rsm/systems/"+service.UID+"/environments", `{"kind":"qa","name":"QA"}`, 422, "")
	var comp struct {
		ID string `json:"component_id"`
	}
	_ = json.Unmarshal(send("POST", "/api/v1/rsm/environments/"+env.ID+"/components", `{"name":"Сервер приложений","critical":true,"baseline":{"software":{"Sample":""}}}`, 201, "Component"), &comp)
	var rule struct {
		ID string `json:"rule_id"`
	}
	_ = json.Unmarshal(send("POST", "/api/v1/rsm/components/"+comp.ID+"/rules", `{"kind":"hostname_glob","pattern":"crm-app-*","mode":"propose"}`, 201, "Rule"), &rule)
	send("POST", "/api/v1/rsm/components/"+comp.ID+"/rules", `{"kind":"ad_ou","pattern":"OU=x"}`, 422, "")

	h1, h2, loose := host("crm-app-01"), host("crm-db-01"), host("orphan-01")
	var proposals struct {
		Items []struct {
			Binding struct {
				ID string `json:"binding_id"`
			} `json:"binding"`
			AssetName string `json:"asset_name"`
		} `json:"items"`
	}
	_ = json.Unmarshal(get("/api/v1/rsm/proposals", "ProposalList"), &proposals)
	if len(proposals.Items) != 1 || proposals.Items[0].AssetName != "crm-app-01" {
		t.Fatalf("proposal after ingest: %+v", proposals)
	}
	send("POST", "/api/v1/rsm/proposals/"+proposals.Items[0].Binding.ID+"/confirm", `{}`, 200, "Binding")
	send("POST", "/api/v1/rsm/proposals/"+proposals.Items[0].Binding.ID+"/confirm", `{}`, 404, "")
	var bulk struct {
		Bound int `json:"bound"`
	}
	_ = json.Unmarshal(send("POST", "/api/v1/rsm/components/"+comp.ID+"/bindings", `{"asset_uids":["`+h2+`","`+h1+`"]}`, 200, "BindResult"), &bulk)
	if bulk.Bound != 1 {
		t.Fatalf("bulk bind: %+v", bulk)
	}
	send("POST", "/api/v1/rsm/recompute", `{}`, 200, "StateResult")
	var overview struct {
		State *struct {
			Unassigned int `json:"unassigned"`
		} `json:"state"`
		Directions []struct {
			State *struct{ Hosts int } `json:"state"`
		} `json:"directions"`
	}
	_ = json.Unmarshal(get("/api/v1/rsm/overview", "Overview"), &overview)
	if overview.State == nil || overview.State.Unassigned < 1 || len(overview.Directions) != 1 || overview.Directions[0].State == nil || overview.Directions[0].State.Hosts != 2 {
		t.Fatalf("overview: %+v", overview)
	}
	get("/api/v1/rsm/directions", "DirectionList")
	// C53.02: фильтры списка, счётчики сводки, состав системы для правой панели
	var page struct {
		Items []struct {
			Owner *string `json:"business_owner"`
			State struct {
				Fresh    int            `json:"fresh"`
				Problems map[string]int `json:"problems"`
			} `json:"state"`
		} `json:"items"`
	}
	_ = json.Unmarshal(get("/api/v1/rsm/systems?criticality=high,critical&env=prod&direction="+dir.UID, "SystemPage"), &page)
	if len(page.Items) != 1 || page.Items[0].Owner == nil || page.Items[0].State.Fresh != 2 {
		t.Fatalf("filtered systems: %+v", page)
	}
	_ = json.Unmarshal(get("/api/v1/rsm/systems?no_owner=true&criticality=high", "SystemPage"), &page)
	if len(page.Items) != 0 {
		t.Fatalf("system with owner must not match no_owner: %+v", page)
	}
	if code, _, _ := b.request(t, "GET", "/api/v1/rsm/systems?criticality=huge", "", "", "", nil); code != 422 {
		t.Fatalf("unknown criticality: %d", code)
	}
	var counters struct {
		Counters struct {
			Systems  int `json:"systems"`
			Critical int `json:"critical"`
		} `json:"counters"`
		Unassigned int `json:"unassigned"`
	}
	_ = json.Unmarshal(get("/api/v1/rsm/overview", "Overview"), &counters)
	if counters.Counters.Systems < 1 || counters.Counters.Critical < 1 || counters.Unassigned < 1 {
		t.Fatalf("overview counters: %+v", counters)
	}
	var comp2 struct {
		Sites        int `json:"sites"`
		Environments []struct {
			Components []struct {
				Hosts []struct {
					Name string `json:"name"`
				} `json:"hosts"`
				More int `json:"more"`
			} `json:"components"`
		} `json:"environments"`
	}
	_ = json.Unmarshal(get("/api/v1/rsm/systems/"+service.UID+"/composition", "Composition"), &comp2)
	if comp2.Sites != 1 || len(comp2.Environments) != 1 || len(comp2.Environments[0].Components[0].Hosts) != 2 {
		t.Fatalf("composition: %+v", comp2)
	}
	_ = json.Unmarshal(get("/api/v1/rsm/systems/"+service.UID+"/composition?q=crm-db", "Composition"), &comp2)
	if len(comp2.Environments) != 1 || len(comp2.Environments[0].Components[0].Hosts) != 1 || comp2.Environments[0].Components[0].Hosts[0].Name != "crm-db-01" {
		t.Fatalf("composition search: %+v", comp2)
	}
	_ = json.Unmarshal(get("/api/v1/rsm/systems/"+service.UID+"/composition?q=nothing-here", "Composition"), &comp2)
	if len(comp2.Environments) != 0 {
		t.Fatalf("composition search without hits: %+v", comp2)
	}
	get("/api/v1/rsm/systems?limit=10", "SystemPage")
	get("/api/v1/rsm/systems?color=red", "SystemPage")
	if code, _, _ := b.request(t, "GET", "/api/v1/rsm/systems?color=pink", "", "", "", nil); code != 422 {
		t.Fatalf("unknown color filter: %d", code)
	}
	var detail struct {
		Environments []struct {
			Components []struct {
				State *struct{ Hosts int } `json:"state"`
			} `json:"components"`
		} `json:"environments"`
	}
	_ = json.Unmarshal(get("/api/v1/rsm/systems/"+service.UID, "SystemDetail"), &detail)
	if len(detail.Environments) != 1 || len(detail.Environments[0].Components) != 1 || detail.Environments[0].Components[0].State.Hosts != 2 {
		t.Fatalf("system tree: %+v", detail)
	}
	var cd struct {
		Hosts []struct {
			AssetUID  string `json:"asset_uid"`
			Name      string `json:"name"`
			BindingID string `json:"binding_id"`
			Primary   bool   `json:"is_primary"`
		} `json:"hosts"`
		Rules []json.RawMessage `json:"rules"`
	}
	_ = json.Unmarshal(get("/api/v1/rsm/components/"+comp.ID+"?limit=1", "ComponentDetail"), &cd)
	if len(cd.Hosts) != 1 || len(cd.Rules) != 1 || cd.Hosts[0].Name == "" || !cd.Hosts[0].Primary {
		t.Fatalf("component detail: %+v", cd)
	}
	var un struct {
		Items []struct {
			AssetUID string `json:"asset_uid"`
		} `json:"items"`
	}
	_ = json.Unmarshal(get("/api/v1/rsm/unassigned?limit=500", "UnassignedPage"), &un)
	found := false
	for _, x := range un.Items {
		found = found || x.AssetUID == loose
	}
	if !found {
		t.Fatal("loose host missing from unassigned")
	}
	var ar struct {
		State    json.RawMessage `json:"state"`
		Bindings []struct {
			Binding struct {
				ID string `json:"binding_id"`
			} `json:"binding"`
			System string `json:"system_name"`
		} `json:"bindings"`
	}
	_ = json.Unmarshal(get("/api/v1/assets/"+h2+"/rsm", "AssetRSM"), &ar)
	if len(ar.Bindings) != 1 || ar.Bindings[0].System != "CRM" || string(ar.State) == "null" {
		t.Fatalf("asset rsm: %+v", ar)
	}
	send("POST", "/api/v1/rsm/bindings/"+ar.Bindings[0].Binding.ID+"/primary", `{}`, 200, "Binding")
	send("POST", "/api/v1/rsm/bindings/"+ar.Bindings[0].Binding.ID+"/unbind", `{}`, 200, "Done")
	send("POST", "/api/v1/rsm/bindings/"+ar.Bindings[0].Binding.ID+"/unbind", `{}`, 404, "")
	send("POST", "/api/v1/rsm/rules/apply", `{}`, 200, "RuleRunResult")
	send("POST", "/api/v1/rsm/rules/"+rule.ID+"/retire", `{}`, 200, "RuleRetired")
	csv := "surveyscan-rsm-bindings;1\r\nsystem;environment;component;host\r\nCRM;Прод;Сервер приложений;crm-db-01\r\n"
	code, raw, _ := b.request(t, "POST", "/api/v1/rsm/import.csv?dry_run=true", csv, session.CSRFToken, "https://ui.example", map[string]string{"Content-Type": "text/csv; charset=utf-8"})
	if code != 200 {
		t.Fatalf("import dry run: %d %s", code, raw)
	}
	valid("ImportResult", raw)
	if !strings.Contains(string(raw), `"will_bind"`) {
		t.Fatalf("dry run must offer the unbound host: %s", raw)
	}
}
