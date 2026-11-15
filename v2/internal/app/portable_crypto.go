package app

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/QgMixtate/surveyscan/v2/internal/portable"
)

// Ключ шифрования portable-пакетов организации (C23, решение пользователя 2026-11-15): закрытая часть — в хранилище
// секретов центра (OpenBao KV или приватные файлы), открытая подставляется в команду init в Web. Один ключ на
// организацию; смена ключа не поддерживается (пакеты, зашифрованные прежним ключом, иначе стали бы нечитаемыми).
const portableEncryptionSecret = "portable-encryption"

var ErrPortableEncryptionKey = errors.New("portable encryption key not configured")

// PortableEncryption — открытый ключ шифрования для init.
type PortableEncryption struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

func (r *Registry) portableEncryptionPrivate(ctx context.Context, tenant string) ([]byte, bool, error) {
	if r.Secrets == nil {
		return nil, false, ErrSecretsUnavailable
	}
	raw, ok, e := r.Secrets.Get(ctx, tenant, portableEncryptionSecret)
	if e != nil || !ok {
		return nil, false, e
	}
	priv, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if e != nil || len(priv) != 32 {
		return nil, false, errors.New("portable encryption key corrupt")
	}
	return priv, true, nil
}

// PortableEncryptionKey возвращает открытый ключ организации; create=true создаёт его при отсутствии (под
// блокировкой организации: два одновременных запроса не создадут два ключа).
func (r *Registry) PortableEncryptionKey(ctx context.Context, tenant string, create bool) (*PortableEncryption, error) {
	if r.Secrets == nil {
		return nil, ErrSecretsUnavailable
	}
	view := func(priv []byte) (*PortableEncryption, error) {
		pub, e := portable.EncryptionPublic(priv)
		if e != nil {
			return nil, e
		}
		return &PortableEncryption{KeyID: portable.EncryptionKeyID(pub), PublicKey: base64.StdEncoding.EncodeToString(pub)}, nil
	}
	if priv, ok, e := r.portableEncryptionPrivate(ctx, tenant); e != nil {
		return nil, e
	} else if ok {
		return view(priv)
	} else if !create {
		return nil, nil
	}
	tx, e := r.Pool.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended('portable-encryption:'||$1::text,0))", tenant); e != nil {
		return nil, e
	}
	if priv, ok, e := r.portableEncryptionPrivate(ctx, tenant); e != nil {
		return nil, e
	} else if ok {
		return view(priv)
	}
	priv, _, e := portable.GenerateEncryptionKey()
	if e != nil {
		return nil, e
	}
	if e = r.Secrets.Put(ctx, tenant, portableEncryptionSecret, []byte(base64.StdEncoding.EncodeToString(priv))); e != nil {
		return nil, e
	}
	return view(priv)
}

// decryptPortable расшифровывает пакет ключом организации (незашифрованный возвращается как есть).
func (r *Registry) decryptPortable(ctx context.Context, tenant string, pkg []byte) ([]byte, bool, error) {
	if !portable.Encrypted(pkg) {
		return pkg, false, nil
	}
	priv, ok, e := r.portableEncryptionPrivate(ctx, tenant)
	if e != nil {
		return nil, true, e
	}
	if !ok {
		return nil, true, ErrPortableEncryptionKey
	}
	plain, e := portable.Open(priv, pkg)
	return plain, true, e
}
