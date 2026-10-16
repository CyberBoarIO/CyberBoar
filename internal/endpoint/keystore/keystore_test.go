package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
)

func digest(s string) []byte {
	d := sha256.Sum256([]byte(s))
	return d[:]
}

// checkSigns signs with k and verifies the signature with its public key
func checkSigns(t *testing.T, k crypto.Signer) {
	t.Helper()
	d := digest("request")
	sig, err := k.Sign(rand.Reader, d, crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(k.Public().(*ecdsa.PublicKey), d, sig) {
		t.Fatal("the signature doesn't verify")
	}
}

func TestParseStorage(t *testing.T) {
	for _, s := range Storages {
		if got, err := ParseStorage(string(s)); err != nil || got != s {
			t.Errorf("ParseStorage(%q) = %q, %v", s, got, err)
		}
	}
	for _, s := range []string{"", "TPM", "keychain", "file "} {
		if _, err := ParseStorage(s); err == nil {
			t.Errorf("ParseStorage(%q) succeeded", s)
		}
	}
}

func TestFileKey(t *testing.T) {
	k, err := Create(File)
	if err != nil {
		t.Fatal(err)
	}
	if k.Storage != File || k.Skipped != "" {
		t.Fatalf("Storage %q, Skipped %q", k.Storage, k.Skipped)
	}
	checkSigns(t, k)
	l, err := Load(k.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if l.Storage != File || !l.Public().(*ecdsa.PublicKey).Equal(k.Public()) {
		t.Fatal("Load returned another key")
	}
	checkSigns(t, l)
	if err := k.Discard(); err != nil {
		t.Fatal(err)
	}
}

// Every key file Load can't use fully is an error
func TestLoadRefuses(t *testing.T) {
	file, _ := Create(File)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der384, _ := x509.MarshalPKCS8PrivateKey(p384)
	block := func(typ string, b []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}) }
	withHeader := pem.EncodeToMemory(&pem.Block{Type: pemFile, Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte{1}})
	for name, data := range map[string][]byte{
		"empty":        nil,
		"not PEM":      []byte("hello"),
		"two blocks":   append(append([]byte{}, file.KeyFile...), file.KeyFile...),
		"trailing":     append(append([]byte{}, file.KeyFile...), "x"...),
		"headers":      withHeader,
		"unknown type": block("EC PRIVATE KEY", []byte{1}),
		"P-384":        block(pemFile, der384),
		"bad PKCS8":    block(pemFile, []byte{0x30, 0}),
		"bad TPM":      block(pemTPM, []byte{0x30, 0}),
		"bad CNG":      block(pemCNG, []byte("{}")),
	} {
		if _, err := Load(data); err == nil {
			t.Errorf("%s: Load succeeded", name)
		}
	}
}

func TestSignRefusesOtherHashes(t *testing.T) {
	k, _ := Create(File)
	l, _ := Load(k.KeyFile)
	s := &signerFunc{pub: l.Public().(*ecdsa.PublicKey), sign: func([]byte) ([]byte, error) {
		t.Fatal("signed")
		return nil, nil
	}}
	for name, c := range map[string]struct {
		d    []byte
		opts crypto.SignerOpts
	}{
		"SHA-384":  {make([]byte, 48), crypto.SHA384},
		"short":    {make([]byte, 31), crypto.SHA256},
		"no opts":  {make([]byte, 32), nil},
		"unhashed": {make([]byte, 32), crypto.Hash(0)},
	} {
		if _, err := s.Sign(rand.Reader, c.d, c.opts); err == nil {
			t.Errorf("%s: Sign succeeded", name)
		}
	}
}

const isWindows = runtime.GOOS == "windows"

// noTPM is a machine without a TPM.
func noTPM() (transport.TPMCloser, error) { return nil, ErrUnavailable }

func TestAutoFallsBackWithoutTPM(t *testing.T) {
	if _, err := createWith(TPM, noTPM); !errors.Is(err, ErrUnavailable) && !isWindows {
		t.Fatalf("Create(TPM) without a TPM: %v", err)
	}
	k, err := createWith(Auto, noTPM)
	if err != nil {
		t.Fatal(err)
	}
	if !isWindows && (k.Storage != File || !strings.Contains(k.Skipped, "no tpm") || !strings.Contains(k.Skipped, "no os")) {
		t.Fatalf("Storage %q, Skipped %q", k.Storage, k.Skipped)
	}
	checkSigns(t, k)
	if err := k.Discard(); err != nil {
		t.Fatal(err)
	}
}

// A store that signs with some other key is caught before the signature is used
func TestSignatureFromAnotherKey(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	d := digest("x")
	r, s, err := ecdsa.Sign(rand.Reader, other, d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := derSignature(&k.PublicKey, d, r, s); err == nil {
		t.Fatal("accepted another key's signature")
	}
	r, s, _ = ecdsa.Sign(rand.Reader, k, d)
	if _, err := derSignature(&k.PublicKey, d, r, s); err != nil {
		t.Fatal(err)
	}
}
