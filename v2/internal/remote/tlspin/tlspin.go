// Package tlspin — проверка HTTPS-сервера коннекторов платформ (C57: vSphere, oVirt/zVirt и др.), как у WinRM (C51.03):
// по CA, заданному администратором, с проверкой имени — либо по закреплённому отпечатку SHA-256 сертификата сервера
// (запомнен при первом подключении, как known_hosts у SSH). Отключение проверки не поддерживается.
package tlspin

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"regexp"
	"strconv"
	"time"
)

var (
	// ErrPolicy — не задан способ проверки сервера.
	ErrPolicy = errors.New("server verification not configured")
	// ErrCertChanged — сертификат сервера не совпал с закреплённым отпечатком.
	ErrCertChanged = errors.New("server certificate changed (cert_changed)")

	pinRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// SHA256 — отпечаток SHA-256 DER-сертификата (строчные hex).
func SHA256(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// Config — TLS-настройка: CAPEM (с именем serverName, иначе host) или pin; ни того ни другого — ErrPolicy.
func Config(caPEM []byte, serverName, host, pin string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	switch {
	case len(caPEM) > 0:
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, ErrPolicy
		}
		cfg.RootCAs = pool
		if cfg.ServerName == "" {
			cfg.ServerName = host
		}
	case pinRe.MatchString(pin):
		// цепочка не строится: доверие — ровно этому сертификату
		cfg.InsecureSkipVerify = true //nolint:gosec // проверка — VerifyConnection по закреплённому отпечатку
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || SHA256(cs.PeerCertificates[0].Raw) != pin {
				return ErrCertChanged
			}
			return nil
		}
	default:
		return nil, ErrPolicy
	}
	return cfg, nil
}

// Fetch — сертификат сервера без входа (для закрепления при первом подключении): отпечаток SHA-256 DER.
func Fetch(host string, port int, serverName string, timeout time.Duration) (string, error) {
	//nolint:gosec // только чтение сертификата для закрепления; учётные данные по этому соединению не передаются
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, ServerName: serverName}
	raw, err := (&net.Dialer{Timeout: timeout}).Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", err
	}
	defer raw.Close()
	c := tls.Client(raw, cfg)
	_ = c.SetDeadline(time.Now().Add(timeout))
	if err = c.Handshake(); err != nil {
		return "", err
	}
	certs := c.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("no server certificate")
	}
	return SHA256(certs[0].Raw), nil
}
