package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"cyberboar.dev/cyberboar/internal/endpoint/strictjson"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// On Windows the key lives in a CNG key storage provider. That is either
// the Platform Crypto Provider, which keeps it in the TPM, or the Software
// Key Storage Provider, which keeps it encrypted with DPAPI under the current
// account (SYSTEM, for a machine-wide install) and refuses to export it. The
// key is a per-account key, so another account, administrators included,
// can't open it by name. The key file records the provider, the key's name
// and its public key, and Load checks the provider's key against that public key

// The providers, by their registered names
const (
	platformProvider = "Microsoft Platform Crypto Provider"
	softwareProvider = "Microsoft Software Key Storage Provider"
)

var (
	ncrypt                  = windows.NewLazySystemDLL("ncrypt.dll")
	procOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procCreatePersistedKey  = ncrypt.NewProc("NCryptCreatePersistedKey")
	procOpenKey             = ncrypt.NewProc("NCryptOpenKey")
	procSetProperty         = ncrypt.NewProc("NCryptSetProperty")
	procGetProperty         = ncrypt.NewProc("NCryptGetProperty")
	procFinalizeKey         = ncrypt.NewProc("NCryptFinalizeKey")
	procExportKey           = ncrypt.NewProc("NCryptExportKey")
	procSignHash            = ncrypt.NewProc("NCryptSignHash")
	procDeleteKey           = ncrypt.NewProc("NCryptDeleteKey")
	procFreeObject          = ncrypt.NewProc("NCryptFreeObject")
)

const (
	ncryptSilentFlag    = 0x40       // NCRYPT_SILENT_FLAG, so no UI is shown that a service can't answer
	ncryptPersistFlag   = 0x80000000 // NCRYPT_PERSIST_FLAG
	exportAllow         = 0x1        // NCRYPT_ALLOW_EXPORT_FLAG
	exportAllowPlain    = 0x2        // NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG
	exportAllowArchive  = 0x4        // NCRYPT_ALLOW_ARCHIVING_FLAG
	exportAllowPlainArc = 0x8        // NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG
	eccPublicP256Magic  = 0x31534345 // BCRYPT_ECDSA_PUBLIC_P256_MAGIC, "ECS1"
)

// cngError turns a SECURITY_STATUS into an error, nil for success
func cngError(what string, r uintptr) error {
	if r == 0 {
		return nil
	}
	return fmt.Errorf("%s: %w", what, windows.Errno(r))
}

// utf16 returns s as a NUL-terminated UTF-16 string for the CNG calls
func utf16(s string) *uint16 {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		panic(err) // only constants and names this file made reach here
	}
	return p
}

// freeObject releases a CNG handle
func freeObject(h uintptr) { _, _, _ = procFreeObject.Call(h) }

// openProvider opens a key storage provider
func openProvider(name string) (uintptr, error) {
	if err := procOpenStorageProvider.Find(); err != nil {
		return 0, fmt.Errorf("ncrypt.dll: %v: %w", err, ErrUnavailable)
	}
	var h uintptr
	r, _, _ := procOpenStorageProvider.Call(uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(utf16(name))), 0)
	if err := cngError("opening the "+name, r); err != nil {
		return 0, err
	}
	return h, nil
}

// cngKeyFile is what a CNG key file holds, as JSON in the PEM block
type cngKeyFile struct {
	Provider  string `json:"provider"`
	Name      string `json:"name"`
	PublicKey []byte `json:"publicKey"` // PKIX DER
}

func createTPM(tpmOpener) (*Key, error) { return createCNG(platformProvider, TPM) }
func createOS() (*Key, error)           { return createCNG(softwareProvider, OS) }

// storageOf returns the Storage a provider's keys are kept in, and whether
// this package uses that provider at all
func storageOf(provider string) (Storage, bool) {
	switch provider {
	case platformProvider:
		return TPM, true
	case softwareProvider:
		return OS, true
	}
	return "", false
}

// createCNG makes a new persisted ECDSA P-256 key named for this endpoint in
// provider. A key in the OS store is made non-exportable before it is
// finished, so it never exists in an exportable state
func createCNG(provider string, s Storage) (*Key, error) {
	prov, err := openProvider(provider)
	if err != nil {
		return nil, err
	}
	defer freeObject(prov)
	name := brand.Name + "-endpoint-" + strings.ToLower(rand.Text())
	var key uintptr
	r, _, _ := procCreatePersistedKey.Call(prov, uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(utf16("ECDSA_P256"))), uintptr(unsafe.Pointer(utf16(name))), 0, ncryptSilentFlag)
	if err := cngError("creating a key in the "+provider, r); err != nil {
		return nil, err
	}
	finalized := false
	defer func() {
		if !finalized {
			freeObject(key)
		}
	}()
	if s == OS {
		// The software provider's default follows group policy, which can
		// allow export, and this key must never leave the machine
		var policy uint32
		r, _, _ = procSetProperty.Call(key, uintptr(unsafe.Pointer(utf16("Export Policy"))),
			uintptr(unsafe.Pointer(&policy)), 4, ncryptPersistFlag|ncryptSilentFlag)
		if err := cngError("making the key non-exportable", r); err != nil {
			return nil, err
		}
	}
	r, _, _ = procFinalizeKey.Call(key, ncryptSilentFlag)
	if err := cngError("finishing the key in the "+provider, r); err != nil {
		return nil, err
	}
	finalized = true
	discard := func() error { return deleteCNG(provider, name) }
	pub, err := checkCNGKey(key, s)
	freeObject(key)
	if err != nil {
		_ = discard()
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		_ = discard()
		return nil, err
	}
	data, _ := json.Marshal(cngKeyFile{Provider: provider, Name: name, PublicKey: spki})
	return &Key{
		Signer:  &signerFunc{pub: pub, sign: cngSign(provider, name, pub)},
		Storage: s,
		KeyFile: pem.EncodeToMemory(&pem.Block{Type: pemCNG, Bytes: data}),
		discard: discard,
	}, nil
}

// checkCNGKey returns an open key's public key, after checking that the
// software provider won't export it. The Platform Crypto Provider never
// exports a private key, so its policy isn't read
func checkCNGKey(key uintptr, s Storage) (*ecdsa.PublicKey, error) {
	if s == OS {
		var policy, n uint32
		r, _, _ := procGetProperty.Call(key, uintptr(unsafe.Pointer(utf16("Export Policy"))),
			uintptr(unsafe.Pointer(&policy)), 4, uintptr(unsafe.Pointer(&n)), ncryptSilentFlag)
		if err := cngError("reading the key's export policy", r); err != nil {
			return nil, err
		}
		if n != 4 || policy&(exportAllow|exportAllowPlain|exportAllowArchive|exportAllowPlainArc) != 0 {
			return nil, errors.New("the key in the Windows key store can be exported")
		}
	}
	var blob [8 + 64]byte
	var n uint32
	r, _, _ := procExportKey.Call(key, 0, uintptr(unsafe.Pointer(utf16("ECCPUBLICBLOB"))), 0,
		uintptr(unsafe.Pointer(&blob[0])), uintptr(len(blob)), uintptr(unsafe.Pointer(&n)), ncryptSilentFlag)
	if err := cngError("reading the public key", r); err != nil {
		return nil, err
	}
	if n != uint32(len(blob)) || binary.LittleEndian.Uint32(blob[0:]) != eccPublicP256Magic ||
		binary.LittleEndian.Uint32(blob[4:]) != 32 {
		return nil, errors.New("the key in the Windows key store is not an ECDSA P-256 key")
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append([]byte{4}, blob[8:]...))
	if err != nil {
		return nil, errors.New("the key in the Windows key store is not on P-256")
	}
	return pub, nil
}

// openCNG opens the key name in provider
func openCNG(provider, name string) (prov, key uintptr, err error) {
	prov, err = openProvider(provider)
	if err != nil {
		return 0, 0, err
	}
	r, _, _ := procOpenKey.Call(prov, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(utf16(name))), 0, ncryptSilentFlag)
	if err := cngError("opening the endpoint key "+name+" in the "+provider, r); err != nil {
		freeObject(prov)
		return 0, 0, err
	}
	return prov, key, nil
}

// deleteCNG deletes the named key from provider
func deleteCNG(provider, name string) error {
	prov, key, err := openCNG(provider, name)
	if err != nil {
		return err
	}
	defer freeObject(prov)
	r, _, _ := procDeleteKey.Call(key, ncryptSilentFlag)
	if err := cngError("deleting the key", r); err != nil {
		freeObject(key) // NCryptDeleteKey frees the handle only when it succeeds
		return err
	}
	return nil
}

// cngSign returns a signing function that opens the key by name for each
// signature, so no handle is kept between calls
func cngSign(provider, name string, pub *ecdsa.PublicKey) func([]byte) ([]byte, error) {
	return func(digest []byte) ([]byte, error) {
		prov, key, err := openCNG(provider, name)
		if err != nil {
			return nil, err
		}
		defer freeObject(prov)
		defer freeObject(key)
		var sig [64]byte
		var n uint32
		r, _, _ := procSignHash.Call(key, 0, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
			uintptr(unsafe.Pointer(&sig[0])), uintptr(len(sig)), uintptr(unsafe.Pointer(&n)), ncryptSilentFlag)
		if err := cngError("signing with the endpoint key", r); err != nil {
			return nil, err
		}
		if n != uint32(len(sig)) {
			return nil, errors.New("the Windows key store answered with a malformed signature")
		}
		return derSignature(pub, digest, new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	}
}

// loadCNG reads a CNG key file and checks that its key is in the provider
// it names, with the public key it records
func loadCNG(data []byte) (*Key, error) {
	var f cngKeyFile
	if err := strictjson.Decode(data, &f); err != nil {
		return nil, fmt.Errorf("not a Windows key store key file: %v", err)
	}
	s, ok := storageOf(f.Provider)
	if !ok {
		return nil, fmt.Errorf("the key file names %q, not a key store this endpoint uses", f.Provider)
	}
	if !strings.HasPrefix(f.Name, brand.Name+"-endpoint-") || strings.IndexByte(f.Name, 0) >= 0 {
		return nil, fmt.Errorf("the key file names %q, not an endpoint key", f.Name)
	}
	want, err := x509.ParsePKIXPublicKey(f.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("the key file's public key: %v", err)
	}
	prov, key, err := openCNG(f.Provider, f.Name)
	if err != nil {
		return nil, err
	}
	defer freeObject(prov)
	defer freeObject(key)
	pub, err := checkCNGKey(key, s)
	if err != nil {
		return nil, err
	}
	if !pub.Equal(want) {
		return nil, fmt.Errorf("the key %s in the %s is not the one the key file records", f.Name, f.Provider)
	}
	return &Key{Signer: &signerFunc{pub: pub, sign: cngSign(f.Provider, f.Name, pub)}, Storage: s}, nil
}
