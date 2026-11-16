package collector

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/enrollpin"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// Установка collector по коду (C52.01): адрес центра + код + отпечаток → ключи на этой машине, регистрация,
// enroll в центре и готовая конфигурация в каталоге (0600). Закрытые ключи никуда не передаются.

type RegisterOptions struct {
	CenterURL   string
	Code        string
	Fingerprint string
	Dir         string // каталог конфигурации и ключей (например, /etc/surveyscan-collector)
	StateDir    string // каталог состояния (очередь, учётки целей)
	Listen      string // адрес приёма агентов, по умолчанию 0.0.0.0:8443
	Hostname    string
}

func pemKey(key ed25519.PrivateKey) []byte {
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func writePrivateFile(path string, b []byte) error {
	tmp := path + ".tmp"
	if e := os.WriteFile(tmp, b, 0o600); e != nil {
		return e
	}
	return os.Rename(tmp, path)
}

// Register — полная установка collector; повторный запуск при существующей конфигурации — отказ.
func Register(ctx context.Context, o RegisterOptions) (string, error) {
	u, e := url.Parse(o.CenterURL)
	if e != nil || u.Scheme != "https" || u.Host == "" {
		return "", errors.New("адрес центра: https://host[:port]")
	}
	if !filepath.IsAbs(o.Dir) || !filepath.IsAbs(o.StateDir) {
		return "", errors.New("каталоги должны быть абсолютными")
	}
	config := filepath.Join(o.Dir, "collector.json")
	if _, e = os.Stat(config); e == nil {
		return "", errors.New("конфигурация уже существует: collector зарегистрирован")
	}
	if o.Listen == "" {
		o.Listen = "0.0.0.0:8443"
	}
	ca, caPEM, e := enrollpin.FetchPinnedCA(ctx, o.CenterURL, o.Fingerprint)
	if e != nil {
		return "", e
	}
	for _, d := range []string{o.Dir, o.StateDir, filepath.Join(o.StateDir, "credentials"), filepath.Join(o.StateDir, "spool")} {
		if e = os.MkdirAll(d, 0o700); e != nil {
			return "", e
		}
	}
	_, tlsKey, _ := ed25519.GenerateKey(rand.Reader)
	signPublic, signKey, _ := ed25519.GenerateKey(rand.Reader)
	csrDER, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "untrusted-subject"}}, tlsKey)
	if e != nil {
		return "", e
	}
	sum := sha256.Sum256(csrDER)
	source := identifier.New()
	public := base64.RawURLEncoding.EncodeToString(signPublic)
	host := o.Hostname
	if host == "" {
		host, _ = os.Hostname()
	}
	var result struct {
		Grant contracts.EnrollmentGrant `json:"grant"`
	}
	if e = enrollpin.PostRegistration(ctx, o.CenterURL, ca, u.Hostname(), map[string]string{"registration_code": o.Code, "source_id": source, "csr_sha256": hex.EncodeToString(sum[:]),
		"signing_public_key": public, "hostname": host}, &result); e != nil {
		return "", e
	}
	if result.Grant.SourceID != source {
		return "", errors.New("код выдан не для collector")
	}
	// enroll в центре — доверие только закреплённому УЦ, имя сервера — из адреса центра
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}}
	body, _ := json.Marshal(contracts.EnrollmentRequest{GrantID: result.Grant.ID, SourceID: source, CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), PublicKey: public})
	req, e := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(o.CenterURL, "/")+"/api/v1/machine/enroll", bytes.NewReader(body))
	if e != nil {
		return "", e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+result.Grant.Token)
	resp, e := client.Do(req)
	if e != nil {
		return "", fmt.Errorf("enroll: нет связи с центром: %w", e)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 201 {
		return "", fmt.Errorf("enroll отклонён: %d %s", resp.StatusCode, bytes.TrimSpace(raw))
	}
	var enrolled contracts.EnrollmentResult
	if e = json.Unmarshal(raw, &enrolled); e != nil || enrolled.SourceID != source || enrolled.Chain == "" {
		return "", errors.New("enroll: неверный ответ центра")
	}
	files := map[string][]byte{"ca.pem": caPEM, "collector.pem": []byte(enrolled.Chain), "collector.key": pemKey(tlsKey), "origin-signing.key": pemKey(signKey)}
	for name, b := range files {
		if e = writePrivateFile(filepath.Join(o.Dir, name), b); e != nil {
			return "", e
		}
	}
	cfg := Config{SourceID: source, CredentialState: filepath.Join(o.StateDir, "credentials"), SigningKey: filepath.Join(o.Dir, "origin-signing.key"), Listen: o.Listen,
		CenterURL: strings.TrimRight(o.CenterURL, "/"), Certificate: filepath.Join(o.Dir, "collector.pem"), PrivateKey: filepath.Join(o.Dir, "collector.key"),
		CA: filepath.Join(o.Dir, "ca.pem"), Spool: filepath.Join(o.StateDir, "spool"), Limit: 64 << 20}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if e = writePrivateFile(config, b); e != nil {
		return "", e
	}
	return source, nil
}
