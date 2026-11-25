package cmdb

import (
	"testing"
	"time"
)

func TestBiosUUIDFormsSwapsFirstThreeGroups(t *testing.T) {
	got := BiosUUIDForms("564D1A2B-3C4D-5E6F-7081-92A3B4C5D6E7")
	if len(got) != 2 || got[0] != "564d1a2b-3c4d-5e6f-7081-92a3b4c5d6e7" || got[1] != "2b1a4d56-4d3c-6f5e-7081-92a3b4c5d6e7" {
		t.Fatalf("forms: %v", got)
	}
	back := BiosUUIDForms(got[1])
	if len(back) != 2 || back[1] != got[0] {
		t.Fatalf("swap is not an involution: %v", back)
	}
	for _, bad := range []string{"", "not-a-uuid", "00000000-0000-0000-0000-000000000000", "03000200-0400-0500-0006-000700080009"} {
		if BiosUUIDForms(bad) != nil {
			t.Fatalf("placeholder accepted: %q", bad)
		}
	}
}

func TestValidatePlatformSnapshot(t *testing.T) {
	id := "11111111-2222-4333-8444-555555555555"
	ok := PlatformSnapshot{Major: 1, SnapshotID: id, Tenant: id, Source: id, Generation: id, Platform: "kvm", Instance: "kvm01", CollectedAt: time.Now(), Complete: true,
		Objects:   []PlatformObject{{Ref: "host", Kind: "host", Name: "kvm01", MACs: []string{}, Attrs: map[string]any{"cpus": 8.0}}, {Ref: "vm1", Kind: "vm", Name: "web", Attrs: map[string]any{"state": "running"}}},
		Relations: []PlatformRelation{{From: "vm1", Type: "runs_on", To: "host"}}, Errors: []string{}}
	if e := ValidatePlatformSnapshot(ok); e != nil {
		t.Fatalf("valid snapshot rejected: %v", e)
	}
	cases := map[string]func(s *PlatformSnapshot){
		"platform": func(s *PlatformSnapshot) { s.Platform = "xen" },
		"dangling rel": func(s *PlatformSnapshot) {
			s.Relations = []PlatformRelation{{From: "vm1", Type: "runs_on", To: "nope"}}
		},
		"dup ref":   func(s *PlatformSnapshot) { s.Objects = append(s.Objects, s.Objects[0]) },
		"attr name": func(s *PlatformSnapshot) { s.Objects[0].Attrs = map[string]any{"Bad-Name": 1.0} },
		"attr type": func(s *PlatformSnapshot) { s.Objects[0].Attrs = map[string]any{"nested": map[string]any{}} },
		"future":    func(s *PlatformSnapshot) { s.CollectedAt = time.Now().Add(time.Hour) },
		"major":     func(s *PlatformSnapshot) { s.Major = 2 },
	}
	for name, mutate := range cases {
		s := ok
		s.Objects = append([]PlatformObject{}, ok.Objects...)
		mutate(&s)
		if ValidatePlatformSnapshot(s) == nil {
			t.Fatalf("%s: invalid snapshot accepted", name)
		}
	}
}
