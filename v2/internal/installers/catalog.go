// Package installers — файлы установки из подписанного выпуска (C52.04, раздача из Web).
//
// Выпуск (scripts/release.py build --installers) кладёт пакеты в payload/installers/ вместе с index.json;
// их SHA-256 и размер — в подписанном manifest выпуска. Центр отдаёт файл, только если его байты совпадают с
// manifest; подпись manifest проверяется открытым ключом выпуска, если он задан центру.
package installers

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

// MaxFileBytes — предел одного файла (MSI collector ~10 МБ, архивы ~10 МБ): защита памяти центра.
const MaxFileBytes = 128 << 20

var (
	ErrNotFound = errors.New("installer not found")
	ErrMismatch = errors.New("installer does not match the signed release manifest")
	nameRE      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~+-]{0,159}$`)
)

// File — один файл установки (описание из index.json, размер и SHA-256 — из подписанного manifest).
type File struct {
	Name      string `json:"name"`
	Component string `json:"component"` // agent | collector | portable
	OS        string `json:"os"`        // linux | windows
	Arch      string `json:"arch"`
	Format    string `json:"format"` // deb | rpm | tar.gz | msi | zip | exe | bin
	Bytes     int64  `json:"bytes"`
	SHA256    string `json:"sha256"`
}

// Catalog — файлы установки выпуска, который сейчас работает в центре.
type Catalog struct {
	dir               string
	Version           string `json:"release_version"`
	ManifestSHA256    string `json:"manifest_sha256"`
	SignatureVerified bool   `json:"signature_verified"`
	Files             []File `json:"files"`
	byName            map[string]File
}

type manifest struct {
	Format  string `json:"format"`
	Version string `json:"version"`
	Files   map[string]struct {
		SHA256 string `json:"sha256"`
		Bytes  int64  `json:"bytes"`
	} `json:"files"`
}

type index struct {
	Format string `json:"format"`
	Files  []File `json:"files"`
}

// Load читает release-manifest.json (и .sig) из каталога установленного выпуска и installers/index.json.
// publicKeyPEM — открытый ключ выпуска (PKIX PEM, Ed25519); пустой — подпись не проверяется центром.
func Load(releaseDir string, publicKeyPEM []byte) (*Catalog, error) {
	raw, e := readLimited(filepath.Join(releaseDir, "release-manifest.json"), 16<<20)
	if e != nil {
		return nil, e
	}
	var m manifest
	if e = json.Unmarshal(raw, &m); e != nil || m.Format != "surveyscan-release-v1" || m.Version == "" {
		return nil, errors.New("release manifest unreadable")
	}
	sum := sha256.Sum256(raw)
	c := &Catalog{dir: filepath.Join(releaseDir, "installers"), Version: m.Version, ManifestSHA256: hex.EncodeToString(sum[:]), byName: map[string]File{}}
	if len(bytes.TrimSpace(publicKeyPEM)) > 0 {
		key, e := ed25519Public(publicKeyPEM)
		if e != nil {
			return nil, e
		}
		sig, e := readLimited(filepath.Join(releaseDir, "release-manifest.sig"), 64)
		if e != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(key, raw, sig) {
			return nil, errors.New("release manifest signature invalid")
		}
		c.SignatureVerified = true
	}
	ib, e := readLimited(filepath.Join(c.dir, "index.json"), 1<<20)
	if errors.Is(e, os.ErrNotExist) {
		return c, nil // выпуск без файлов установки
	}
	if e != nil {
		return nil, e
	}
	var ix index
	if e = json.Unmarshal(ib, &ix); e != nil || ix.Format != "surveyscan-installers-v1" {
		return nil, errors.New("installers index unreadable")
	}
	// index.json сам входит в подписанный manifest
	if want, ok := m.Files["installers/index.json"]; !ok || hexSum(ib) != want.SHA256 {
		return nil, ErrMismatch
	}
	for _, f := range ix.Files {
		entry, ok := m.Files["installers/"+f.Name]
		if !nameRE.MatchString(f.Name) || !ok || entry.Bytes <= 0 || entry.Bytes > MaxFileBytes || len(entry.SHA256) != 64 {
			return nil, fmt.Errorf("installer %q not in the release manifest", f.Name)
		}
		if _, dup := c.byName[f.Name]; dup {
			return nil, fmt.Errorf("installer %q listed twice", f.Name)
		}
		f.Bytes, f.SHA256 = entry.Bytes, entry.SHA256
		c.byName[f.Name] = f
		c.Files = append(c.Files, f)
	}
	sort.Slice(c.Files, func(i, j int) bool {
		a, b := c.Files[i], c.Files[j]
		if a.Component != b.Component {
			return a.Component < b.Component
		}
		if a.OS != b.OS {
			return a.OS > b.OS // windows раньше linux
		}
		return a.Name < b.Name
	})
	return c, nil
}

// Read возвращает байты файла после сверки размера и SHA-256 с подписанным manifest (на каждое скачивание).
func (c *Catalog) Read(name string) ([]byte, File, error) {
	f, ok := c.byName[name]
	if !ok || !nameRE.MatchString(name) {
		return nil, File{}, ErrNotFound
	}
	b, e := readLimited(filepath.Join(c.dir, name), MaxFileBytes)
	if e != nil {
		return nil, File{}, ErrMismatch
	}
	if int64(len(b)) != f.Bytes || hexSum(b) != f.SHA256 {
		return nil, File{}, ErrMismatch
	}
	return b, f, nil
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func readLimited(path string, limit int64) ([]byte, error) {
	st, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Size() > limit {
		return nil, errors.New("regular file within limit required")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit+1))
}

func ed25519Public(p []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil, errors.New("release public key: PEM required")
	}
	k, e := x509.ParsePKIXPublicKey(block.Bytes)
	if e != nil {
		return nil, errors.New("release public key unreadable")
	}
	key, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("release public key: Ed25519 required")
	}
	return key, nil
}
