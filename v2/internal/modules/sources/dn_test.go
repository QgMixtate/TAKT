package sources

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

func TestReadableDNShowsDomainComponents(t *testing.T) {
	n := pkix.Name{CommonName: "awm-DC-CA"}
	n.ExtraNames = nil
	seq := pkix.RDNSequence{
		{{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, Value: "local"}},
		{{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, Value: "awm"}},
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "awm-DC-CA"}},
	}
	var parsed pkix.Name
	parsed.FillFromRDNSequence(&seq)
	if got := readableDN(parsed); got != "CN=awm-DC-CA,DC=awm,DC=local" {
		t.Fatalf("readableDN = %q", got)
	}
	if got := readableDN(n); got != "CN=awm-DC-CA" {
		t.Fatalf("plain = %q", got)
	}
}
