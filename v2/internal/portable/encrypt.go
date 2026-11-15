package portable

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// Шифрование portable-пакета ключом центра (C23, решение пользователя 2026-11-15): если флешку с пакетом потеряют,
// инвентарь не прочитать. HPKE RFC 9180 из стандартной библиотеки, одна фиксированная suite: DHKEM(X25519,
// HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM. Шифруется весь подписанный ZIP: подпись источника по-прежнему
// проверяется после расшифровки, шифрование её не заменяет.
//
// Конверт: EncMagic | key_id получателя (16 байт) | HPKE enc||ciphertext. info = EncMagic | key_id: конверт
// нельзя переадресовать другому ключу, не сломав расшифровку.

const EncMagic = "SURVEYSCAN-PORTABLE-ENC-V1\n"

var (
	ErrEncryptedKey = errors.New("portable: package is encrypted for another centre key")
	ErrEnvelope     = errors.New("portable: encrypted package corrupt or wrong key")
)

func kem() hpke.KEM { return hpke.DHKEM(ecdh.X25519()) }

// GenerateEncryptionKey — закрытый ключ центра (32 байта X25519) и его открытый ключ.
func GenerateEncryptionKey() (priv, pub []byte, err error) {
	priv = make([]byte, 32)
	if _, err = rand.Read(priv); err != nil {
		return nil, nil, err
	}
	pub, err = EncryptionPublic(priv)
	return priv, pub, err
}

// EncryptionPublic — открытый ключ по закрытому.
func EncryptionPublic(priv []byte) ([]byte, error) {
	k, err := kem().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

// EncryptionKeyID — первые 16 байт SHA-256 открытого ключа (hex): какому ключу центра адресован пакет.
func EncryptionKeyID(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16])
}

// Encrypted сообщает, что данные — зашифрованный конверт (а не ZIP).
func Encrypted(data []byte) bool { return bytes.HasPrefix(data, []byte(EncMagic)) }

// EnvelopeKeyID — key_id получателя из заголовка конверта.
func EnvelopeKeyID(data []byte) (string, error) {
	if !Encrypted(data) || len(data) < len(EncMagic)+16 {
		return "", ErrEnvelope
	}
	return hex.EncodeToString(data[len(EncMagic) : len(EncMagic)+16]), nil
}

// Seal шифрует пакет открытым ключом центра.
func Seal(pub, plain []byte) ([]byte, error) {
	pk, err := kem().NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	id, _ := hex.DecodeString(EncryptionKeyID(pub))
	head := append([]byte(EncMagic), id...)
	ct, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), head, plain)
	if err != nil {
		return nil, err
	}
	return append(head, ct...), nil
}

// Open расшифровывает конверт закрытым ключом центра. Чужой key_id — ErrEncryptedKey, порча — ErrEnvelope.
func Open(priv, data []byte) ([]byte, error) {
	k, err := kem().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	id, err := EnvelopeKeyID(data)
	if err != nil {
		return nil, err
	}
	if id != EncryptionKeyID(k.PublicKey().Bytes()) {
		return nil, ErrEncryptedKey
	}
	head := data[:len(EncMagic)+16]
	plain, err := hpke.Open(k, hpke.HKDFSHA256(), hpke.AES256GCM(), head, data[len(head):])
	if err != nil {
		return nil, ErrEnvelope
	}
	return plain, nil
}
