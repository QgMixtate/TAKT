package winrminv

import (
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
)

func TestClassifyTLSReasons(t *testing.T) {
	cases := []struct {
		in   error
		want error
	}{
		{fmt.Errorf("Post: tls: %w", x509.UnknownAuthorityError{}), ErrTLSUnknownCA},
		{fmt.Errorf("Post: %w", x509.HostnameError{Certificate: &x509.Certificate{}, Host: "pc"}), ErrTLSName},
		{fmt.Errorf("Post: %w", x509.CertificateInvalidError{Reason: x509.Expired}), ErrTLSExpired},
		{errors.New("remote error: tls: handshake failure"), ErrTLS},
	}
	for _, c := range cases {
		got := classifyKind(c.in)
		if got != c.want || !errors.Is(got, ErrTLS) {
			t.Fatalf("%v → %v, want %v", c.in, got, c.want)
		}
	}
}
