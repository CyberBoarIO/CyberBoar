package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"cyberboar.dev/cyberboar/pkg/brand"
)

// cngKeyFileOf decodes a CNG key file, for tests that rewrite it.
func cngKeyFileOf(t *testing.T, keyFile []byte) cngKeyFile {
	t.Helper()
	b, _ := pem.Decode(keyFile)
	var f cngKeyFile
	if b == nil || b.Type != pemCNG || json.Unmarshal(b.Bytes, &f) != nil {
		t.Fatalf("not a CNG key file: %q", keyFile)
	}
	return f
}

func encodeCNG(f cngKeyFile) []byte {
	data, _ := json.Marshal(f)
	return pem.EncodeToMemory(&pem.Block{Type: pemCNG, Bytes: data})
}

func testCNG(t *testing.T, s Storage) {
	k, err := Create(s)
	if s == TPM && err != nil {
		t.Skipf("no TPM: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	discarded := false
	t.Cleanup(func() {
		if !discarded {
			_ = k.Discard()
		}
	})
	if k.Storage != s {
		t.Fatalf("Storage %q", k.Storage)
	}
	checkSigns(t, k)
	l, err := Load(k.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if l.Storage != s || !l.Public().(*ecdsa.PublicKey).Equal(k.Public()) {
		t.Fatal("Load returned another key")
	}
	checkSigns(t, l)

	f := cngKeyFileOf(t, k.KeyFile)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherPub, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	for name, g := range map[string]func(*cngKeyFile){
		"another public key": func(f *cngKeyFile) { f.PublicKey = otherPub },
		"another provider":   func(f *cngKeyFile) { f.Provider = "Microsoft Smart Card Key Storage Provider" },
		"another key name":   func(f *cngKeyFile) { f.Name = "some-other-key" },
		"a missing key":      func(f *cngKeyFile) { f.Name += "x" },
	} {
		h := f
		g(&h)
		if _, err := Load(encodeCNG(h)); err == nil {
			t.Errorf("%s: Load succeeded", name)
		}
	}
	extra := pem.EncodeToMemory(&pem.Block{Type: pemCNG, Bytes: []byte(`{"provider":"` + f.Provider + `","name":"` + f.Name + `","publicKey":null,"x":1}`)})
	if _, err := Load(extra); err == nil {
		t.Error("an unknown field: Load succeeded")
	}

	if err := k.Discard(); err != nil {
		t.Fatal(err)
	}
	discarded = true
	if _, err := Load(k.KeyFile); err == nil {
		t.Fatal("Load found a discarded key")
	}
}

func TestCNGSoftwareKey(t *testing.T) { testCNG(t, OS) }
func TestCNGPlatformKey(t *testing.T) { testCNG(t, TPM) }

func TestCNGRefusesNULInKeyName(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, provider := range []string{softwareProvider, platformProvider} {
		for _, name := range []string{brand.Name + "-endpoint-\x00x", brand.Name + "-endpoint-x\x00"} {
			t.Run(provider+"/"+name, func(t *testing.T) {
				data := encodeCNG(cngKeyFile{Provider: provider, Name: name, PublicKey: pub})
				if _, err := Load(data); err == nil {
					t.Fatal("loaded a key name containing NUL")
				}
			})
		}
	}
}
