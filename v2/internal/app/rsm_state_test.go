package app

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/cmdb"
)

func TestRSMHostColor(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { v := now.Add(-d); return &v }
	cases := []struct {
		name  string
		in    hostInput
		color string
		code  string
	}{
		{"fresh", hostInput{LastInventory: at(time.Hour), Presence: "present"}, "green", ""},
		{"no inventory", hostInput{Presence: "unknown"}, "grey", "NO_INVENTORY"},
		{"missing without inventory", hostInput{Presence: "missing"}, "red", "HOST_MISSING"},
		{"stale", hostInput{LastInventory: at(30 * time.Hour)}, "yellow", "INVENTORY_STALE"},
		{"lost", hostInput{LastInventory: at(8 * 24 * time.Hour)}, "red", "INVENTORY_LOST"},
		{"conflict", hostInput{LastInventory: at(time.Hour), Conflicts: 1}, "yellow", "RECONCILIATION_CONFLICT"},
		{"deviation", hostInput{LastInventory: at(time.Hour), Deviations: []RSMReason{{Code: "BASELINE_OS"}}}, "yellow", "BASELINE_OS"},
		{"missing beats stale", hostInput{LastInventory: at(30 * time.Hour), Presence: "missing"}, "red", "HOST_MISSING"},
	}
	for _, c := range cases {
		color, reasons := hostColor(c.in, now)
		got := ""
		for _, r := range reasons {
			if r.Code == c.code {
				got = r.Code
			}
		}
		if color != c.color || got != c.code {
			t.Fatalf("%s: color=%s reasons=%+v", c.name, color, reasons)
		}
	}
}

func TestRSMBaselineDeviations(t *testing.T) {
	c := cmdb.TopologyComponent{ID: "c1", Name: "1С", Baseline: json.RawMessage(`{"os":"Windows Server 2022","software":{"1С:Предприятие":"8.3.24","KES":""},"antivirus":"KES 12"}`)}
	os := "Microsoft Windows Server 2019 Standard"
	got := baselineDeviations(c, &os, hostSoftware{"1с:предприятие 8.3 (x86-64)": {"8.3.22.1709"}})
	codes := []string{}
	for _, r := range got {
		codes = append(codes, r.Code)
	}
	if strings.Join(codes, ",") != "BASELINE_OS,BASELINE_SOFTWARE_VERSION,BASELINE_SOFTWARE_MISSING" {
		t.Fatalf("deviations: %+v", got)
	}
	// нет данных о хосте — не отклонение
	if d := baselineDeviations(c, nil, nil); len(d) != 0 {
		t.Fatalf("no host data must not deviate: %+v", d)
	}
	ok := "Windows Server 2022 Datacenter"
	if d := baselineDeviations(c, &ok, hostSoftware{"1с:предприятие 8.3": {"8.3.24.1342"}, "kaspersky kes": {"12.6"}}); len(d) != 0 {
		t.Fatalf("matching host: %+v", d)
	}
}

func TestRSMRollup(t *testing.T) {
	dir := "d1"
	topo := cmdb.Topology{
		Components: []cmdb.TopologyComponent{
			{ID: "app", Environment: "prod", Name: "Сервер приложений", Critical: true},
			{ID: "web", Environment: "prod", Name: "Веб"},
			{ID: "tapp", Environment: "test", Name: "Тест", Critical: true},
			{ID: "empty", Environment: "prod2", Name: "Пусто"},
		},
		Environments: []cmdb.TopologyEnvironment{{ID: "prod", Service: "erp", Kind: "prod"}, {ID: "test", Service: "erp", Kind: "test"}, {ID: "prod2", Service: "bill", Kind: "prod"}},
		Systems:      []cmdb.TopologySystem{{UID: "erp", Name: "ERP", Criticality: "high", Direction: &dir}, {UID: "bill", Name: "Биллинг", Criticality: "low"}},
		Directions:   []string{"d1"},
		Bindings:     map[string][]string{"app": {"h1", "h2"}, "web": {"h3", "h2"}, "tapp": {"h4"}},
	}
	byKey := func(nodes []cmdb.NodeState) map[string]cmdb.NodeState {
		m := map[string]cmdb.NodeState{}
		for _, n := range nodes {
			m[n.Kind+":"+n.ID] = n
		}
		return m
	}
	// 1 из 2 хостов критичного компонента красный → компонент красный → прод красный → ERP (high) красная → компания красная
	m := byKey(rollupRSM(topo, map[string]string{"h1": "red", "h2": "green", "h3": "green", "h4": "green"}, 7))
	for key, want := range map[string]string{"component:app": "red", "component:web": "green", "environment:prod": "red", "system:erp": "red", "direction:d1": "red", "tenant:": "red", "component:empty": "grey", "system:bill": "grey"} {
		if m[key].Color != want {
			t.Fatalf("%s = %s, want %s (%s)", key, m[key].Color, want, m[key].Reasons)
		}
	}
	if m["system:erp"].Hosts != 4 || m["environment:prod"].Hosts != 3 || m["tenant:"].Unassigned != 7 {
		t.Fatalf("distinct host counts: erp=%d prod=%d unassigned=%d", m["system:erp"].Hosts, m["environment:prod"].Hosts, m["tenant:"].Unassigned)
	}
	// красная тестовая среда не делает систему красной; некритичная система не делает компанию красной
	m = byKey(rollupRSM(topo, map[string]string{"h1": "green", "h2": "green", "h3": "green", "h4": "red"}, 0))
	if m["environment:test"].Color != "red" || m["system:erp"].Color != "yellow" || m["tenant:"].Color != "yellow" {
		t.Fatalf("nonprod cap: test=%s erp=%s tenant=%s", m["environment:test"].Color, m["system:erp"].Color, m["tenant:"].Color)
	}
	// 1 красный из 3 — компонент жёлтый
	topo.Bindings["web"] = []string{"h3", "h5", "h6"}
	m = byKey(rollupRSM(topo, map[string]string{"h1": "green", "h2": "green", "h3": "red", "h5": "green", "h6": "green", "h4": "green"}, 0))
	if m["component:web"].Color != "yellow" || m["environment:prod"].Color != "yellow" {
		t.Fatalf("minority red: web=%s prod=%s", m["component:web"].Color, m["environment:prod"].Color)
	}
}
