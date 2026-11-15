package portable

import (
	"bytes"
	"errors"
	"testing"
)

func TestSealOpen(t *testing.T) {
	priv, pub, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("PK\x03\x04 signed zip with inventory hostname=secret-host")
	env, err := Seal(pub, plain)
	if err != nil || !Encrypted(env) || bytes.Contains(env, []byte("secret-host")) {
		t.Fatal("envelope", err)
	}
	if id, _ := EnvelopeKeyID(env); id != EncryptionKeyID(pub) {
		t.Fatal("key id")
	}
	got, err := Open(priv, env)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("open", err)
	}
	other, _, _ := GenerateEncryptionKey()
	if _, err = Open(other, env); !errors.Is(err, ErrEncryptedKey) {
		t.Fatal("other key must be refused by key id", err)
	}
	broken := bytes.Clone(env)
	broken[len(broken)-1] ^= 1
	if _, err = Open(priv, broken); !errors.Is(err, ErrEnvelope) {
		t.Fatal("tampered ciphertext", err)
	}
	if Encrypted(plain) {
		t.Fatal("plain zip is not an envelope")
	}
}
