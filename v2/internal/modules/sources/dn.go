package sources

import (
	"crypto/x509/pkix"
	"strings"
)

// readableDN — pkix.Name.String(), но domainComponent (0.9.2342.19200300.100.1.25) показан как DC=: у AD CS имя CA
// почти всегда с DC=, а OID в Web непонятен (стенд №17).
func readableDN(n pkix.Name) string {
	return strings.ReplaceAll(n.String(), "0.9.2342.19200300.100.1.25=", "DC=")
}
