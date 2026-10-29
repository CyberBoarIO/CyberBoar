package keystore

import (
	"crypto/ecdsa"
	"encoding/pem"
	"testing"
)

// FuzzLoad feeds Load key files: it must return a P-256 key or an error,
// never panic. The fuzzer picks the PEM type and writes the body.
// The seeds are built here so that no key file sits in the repository as text.
func FuzzLoad(f *testing.F) {
	types := []string{pemFile, pemTPM, pemCNG, "PUBLIC KEY"}
	k, _ := Create(File)
	b, _ := pem.Decode(k.KeyFile)
	f.Add(byte(0), b.Bytes)
	f.Add(byte(1), []byte{0x30, 0})
	f.Add(byte(2), []byte(`{"provider":"Microsoft Software Key Storage Provider","name":"x","publicKey":null}`))
	f.Fuzz(func(t *testing.T, kind byte, body []byte) {
		k, err := Load(pem.EncodeToMemory(&pem.Block{Type: types[int(kind)%len(types)], Bytes: body}))
		if err != nil {
			return
		}
		if _, ok := k.Public().(*ecdsa.PublicKey); !ok {
			t.Fatal("Load returned a key that isn't ECDSA")
		}
	})
}
