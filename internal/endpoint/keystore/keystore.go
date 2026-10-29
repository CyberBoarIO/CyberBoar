// Package keystore keeps an endpoint's P-256 private key where it can't be
// copied off the machine, in the TPM or in the operating system's key store,
// with a file as the last resort.
//
// Whichever store holds the key, the endpoint keeps one small file that
// names it, the "key file". For a file key, the key file is the key itself,
// a PEM "PRIVATE KEY". For a TPM key on Linux, it is the TPM's wrapped key
// blob, a "TSS2 PRIVATE KEY", which only the TPM that made it can use. On
// Windows it names a key in a CNG key storage provider. Load reads the key
// file and uses the store it names, and never another. A key file for the
// TPM on a machine whose TPM can't be reached is an error, not a reason to
// fall back.
package keystore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// Storage is where a key is kept.
type Storage string

// These are the places a key can be kept.
// Auto is only a request, which Create resolves to one of the others.
const (
	Auto Storage = "auto" // TPM, else OS, else File
	TPM  Storage = "tpm"  // the TPM, through Linux's /dev/tpmrm0 or Windows' Platform Crypto Provider
	OS   Storage = "os"   // the OS key store, Windows' Software Key Storage Provider, not bound to hardware
	File Storage = "file" // a PEM file, private to the current user
)

// Storages lists the values ParseStorage accepts, in the order Auto tries
// them.
var Storages = []Storage{Auto, TPM, OS, File}

// ParseStorage returns the Storage named s.
func ParseStorage(s string) (Storage, error) {
	for _, v := range Storages {
		if string(v) == s {
			return v, nil
		}
	}
	return "", fmt.Errorf("%q is not a key storage (one of %s)", s, strings.Join(storageNames(), ", "))
}

func storageNames() []string {
	names := make([]string, len(Storages))
	for i, v := range Storages {
		names[i] = string(v)
	}
	return names
}

// Key is an endpoint key and the key file that names it.
type Key struct {
	crypto.Signer         // signs SHA-256 digests, and Public returns an *ecdsa.PublicKey on P-256
	Storage       Storage // where the key is: TPM, OS or File
	KeyFile       []byte  // what to write to the key file

	// Skipped says why Create with Auto didn't use a stronger store, as in
	// "no tpm: <reason>". It is empty when Create used the first store it tried.
	Skipped string

	discard func() error
}

// Discard removes a key Create made whose key file couldn't be written, so
// it doesn't linger in the store unnamed. File and TPM keys live only in
// their key file, so there is nothing to remove.
func (k *Key) Discard() error {
	if k.discard == nil {
		return nil
	}
	return k.discard()
}

// ErrUnavailable is wrapped in the error Create returns for a store this
// machine doesn't have or can't reach.
var ErrUnavailable = errors.New("not available on this machine")

// Create makes a new P-256 key in the store s asks for. With Auto it tries
// the TPM, then the OS store, then a file, and says in Key.Skipped why it
// passed over the stronger ones. With any other value it uses that store or fails.
func Create(s Storage) (*Key, error) { return createWith(s, openPlatformTPM) }

// createWith is Create with the TPM openTPM reaches.
func createWith(s Storage, openTPM tpmOpener) (*Key, error) {
	if s != Auto {
		return create(s, openTPM)
	}
	var skipped []string
	for _, try := range []Storage{TPM, OS} {
		k, err := create(try, openTPM)
		if err == nil {
			k.Skipped = strings.Join(skipped, "; ")
			return k, nil
		}
		skipped = append(skipped, fmt.Sprintf("no %s: %v", try, err))
	}
	k, err := create(File, openTPM)
	if err != nil {
		return nil, err
	}
	k.Skipped = strings.Join(skipped, "; ")
	return k, nil
}

func create(s Storage, openTPM tpmOpener) (*Key, error) {
	switch s {
	case TPM:
		return createTPM(openTPM)
	case OS:
		return createOS()
	case File:
		return createFile()
	}
	return nil, fmt.Errorf("%q is not a key storage", s)
}

// The PEM block types a key file can hold.
const (
	pemFile = "PRIVATE KEY"      // PKCS #8
	pemTPM  = "TSS2 PRIVATE KEY" // the TPM 2.0 key file format (loadable key)
	pemCNG  = "CNG KEY"          // a key in a Windows CNG key storage provider
)

// Load returns the key a key file names. The key file must hold a single
// PEM block and nothing else. The key must be ECDSA P-256 and, in the TPM or
// the OS store, one that store won't export.
func Load(keyFile []byte) (*Key, error) { return load(keyFile, openPlatformTPM) }

// load is Load with the TPM openTPM reaches.
func load(keyFile []byte, openTPM tpmOpener) (*Key, error) {
	b, rest := pem.Decode(keyFile)
	if b == nil || len(b.Headers) > 0 || len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("not a single PEM block")
	}
	var (
		k   *Key
		err error
	)
	switch b.Type {
	case pemFile:
		k, err = loadFile(b.Bytes)
	case pemTPM:
		k, err = loadTPM(b.Bytes, openTPM)
	case pemCNG:
		k, err = loadCNG(b.Bytes)
	default:
		return nil, fmt.Errorf("a PEM %q block is not a key file", b.Type)
	}
	if err != nil {
		return nil, err
	}
	k.KeyFile = keyFile
	return k, nil
}

// createFile makes a key kept in its key file.
func createFile() (*Key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return &Key{Signer: priv, Storage: File, KeyFile: pem.EncodeToMemory(&pem.Block{Type: pemFile, Bytes: der})}, nil
}

func loadFile(der []byte) (*Key, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(*ecdsa.PrivateKey)
	if !ok || priv.Curve != elliptic.P256() {
		return nil, errors.New("not an ECDSA P-256 key")
	}
	return &Key{Signer: priv, Storage: File}, nil
}

// checkDigest refuses anything but a SHA-256 digest. Every signature an
// endpoint makes, for RFC 9421 requests and for TLS 1.3 with a P-256
// certificate, is ECDSA with SHA-256, and the TPM key is created for that scheme alone.
func checkDigest(digest []byte, opts crypto.SignerOpts) error {
	if opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != 32 {
		return errors.New("the endpoint key signs SHA-256 digests only")
	}
	return nil
}

// derSignature checks an ECDSA signature a store returned against the
// public key the key file names, and encodes it as crypto.Signer does
// A store answering with another key's signature is an error here rather than
// a rejected request later.
func derSignature(pub *ecdsa.PublicKey, digest []byte, r, s *big.Int) ([]byte, error) {
	if !ecdsa.Verify(pub, digest, r, s) {
		return nil, errors.New("the key store's signature doesn't verify with the endpoint key")
	}
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}

// signerFunc adapts a signing function to crypto.Signer.
type signerFunc struct {
	pub  *ecdsa.PublicKey
	sign func(digest []byte) ([]byte, error)
}

func (f *signerFunc) Public() crypto.PublicKey { return f.pub }

func (f *signerFunc) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if err := checkDigest(digest, opts); err != nil {
		return nil, err
	}
	return f.sign(digest)
}
