package windowsinventory

import "testing"

func TestUniqueAntivirusKeepsFirstRegistration(t *testing.T) {
	rows := []map[string]any{
		{"kind": "antivirus", "name": "Kaspersky", "provider": "SecurityCenter2", "state": "reported_product_state:266240"},
		{"kind": "antivirus", "name": "Kaspersky", "provider": "SecurityCenter2", "state": "reported_product_state:262144"},
		{"kind": "antivirus", "name": "Windows Defender", "provider": "SecurityCenter2"},
		{"kind": "antivirus", "name": "Kaspersky", "provider": "SecurityCenter2", "state": "reported_product_state:393472"},
	}
	got := uniqueAntivirus(rows)
	if len(got) != 2 || got[0]["state"] != "reported_product_state:266240" || got[1]["name"] != "Windows Defender" {
		t.Fatalf("%v", got)
	}
}
