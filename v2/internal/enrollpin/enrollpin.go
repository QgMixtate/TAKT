package enrollpin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Закрепление центра при установке по коду (C52.01): общий код агента и collector (Go; Rust-агент повторяет то же).

// NormalizeFingerprint — 64 hex-символа нижним регистром (двоеточия и пробелы допускаются при вводе).
func NormalizeFingerprint(v string) string {
	v = strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(v)))
	if len(v) != 64 {
		return ""
	}
	if _, e := hex.DecodeString(v); e != nil {
		return ""
	}
	return v
}

// FetchPinnedCA — сертификат УЦ центра по адресу (collector или центр): отпечаток совпадает с введённым, а сертификат
// сервера этого же соединения выпущен этим УЦ. Иначе — отказ (подмена адреса или не тот центр).
func FetchPinnedCA(ctx context.Context, base, fingerprint string) (*x509.Certificate, []byte, error) {
	fp := NormalizeFingerprint(fingerprint)
	if fp == "" {
		return nil, nil, errors.New("отпечаток центра: нужно 64 шестнадцатеричных символа из Web")
	}
	var leaf *x509.Certificate
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12,
		InsecureSkipVerify: true, // проверка ниже — по закреплённому отпечатку УЦ
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no server certificate")
			}
			leaf = cs.PeerCertificates[0]
			return nil
		}}}}
	req, e := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(base, "/")+"/api/v1/registration/ca", nil)
	if e != nil {
		return nil, nil, e
	}
	resp, e := client.Do(req)
	if e != nil {
		return nil, nil, fmt.Errorf("нет связи: %w", e)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("сервер ответил %d", resp.StatusCode)
	}
	var body struct {
		PEM string `json:"ca_pem"`
	}
	if e = json.Unmarshal(raw, &body); e != nil {
		return nil, nil, errors.New("неверный ответ сервера")
	}
	block, _ := pem.Decode([]byte(body.PEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, errors.New("неверный сертификат центра")
	}
	ca, e := x509.ParseCertificate(block.Bytes)
	if e != nil || !ca.IsCA {
		return nil, nil, errors.New("неверный сертификат центра")
	}
	sum := sha256.Sum256(ca.Raw)
	if hex.EncodeToString(sum[:]) != fp {
		return nil, nil, errors.New("отпечаток центра не совпадает: проверьте адрес и отпечаток из Web")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if leaf == nil {
		return nil, nil, errors.New("no server certificate")
	}
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e != nil {
		return nil, nil, errors.New("сертификат сервера не выпущен центром с этим отпечатком")
	}
	return ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), nil
}

// PostRegistration — код + подготовленная личность → результат регистрации (доверие — только закреплённому УЦ).
func PostRegistration(ctx context.Context, base string, ca *x509.Certificate, serverName string, body any, out any) error {
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: serverName}
	if serverName == "" {
		// collector/центр ещё не известен по имени: цепочка до закреплённого УЦ обязательна, имя проверяется после
		cfg.InsecureSkipVerify = true
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no server certificate")
			}
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			_, e := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			return e
		}
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: cfg}}
	raw, _ := json.Marshal(body)
	req, e := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(base, "/")+"/api/v1/registration", bytes.NewReader(raw))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	resp, e := client.Do(req)
	if e != nil {
		return fmt.Errorf("нет связи: %w", e)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	switch {
	case resp.StatusCode == 201:
		return json.Unmarshal(b, out)
	case resp.StatusCode == 401:
		return errors.New("код не принят: неверный, просрочен, отозван или исчерпан")
	case resp.StatusCode == 409 && bytes.Contains(b, []byte("ALREADY_REGISTERED")):
		return errors.New("эта машина уже зарегистрирована этим кодом")
	default:
		return fmt.Errorf("регистрация отклонена: %d %s", resp.StatusCode, bytes.TrimSpace(b))
	}
}
