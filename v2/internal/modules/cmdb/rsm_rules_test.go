package cmdb

import "testing"

// ISSUES №85/№95: образец «класс/семейство ОС» принимается, класс и семейство — только из справочников.
func TestNormalizeRulePatternAssetClass(t *testing.T) {
	for in, want := range map[string]string{"server": "server", "virtual_machine/windows": "virtual_machine/windows", " Workstation/Linux ": "workstation/linux", "network_device": "network_device"} {
		if got, ok := NormalizeRulePattern("asset_class", in); !ok || got != want {
			t.Fatalf("%q: %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"laptop", "network", "virtual", "server/", "server/solaris", "virtual_machine/windows/x", "/windows"} {
		if _, ok := NormalizeRulePattern("asset_class", in); ok {
			t.Fatalf("%q accepted", in)
		}
	}
}
