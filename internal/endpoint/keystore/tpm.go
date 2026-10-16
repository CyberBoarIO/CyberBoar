package keystore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// A TPM key is an ECDSA P-256 signing key the TPM generated under its
// storage root key. The TPM re-creates the storage root key on demand from
// the owner hierarchy's seed with the TCG's reference template, so nothing is
// persisted in the TPM. The key file holds the key's public area and its
// private area wrapped by the storage root key
// Only this TPM can unwrap it,  so copying the key file to another machine gives nothing
//
// The key file is the TPM 2.0 key file format other tools (OpenSSL's tpm2
// provider, tpm2-tools) read, as a loadable key whose parent is the owner
// hierarchy, with an empty authorization value. The key needs no password
// of its own. Whoever can read the key file and talk to the TPM can sign with
// it, and those are the same people who could read a file key. For a
// machine-wide install that is root or SYSTEM, and /dev/tpmrm0 belongs to
// root and the tss group. What the TPM adds is that the key can't leave the machine

// tpmOpener opens the TPM keys are made and used in, or returns an error
// wrapping ErrUnavailable. Keys use this machine's TPM, which openPlatformTPM opens
type tpmOpener func() (transport.TPMCloser, error)

// oidLoadableKey is the TPM 2.0 key file format's type for a key loaded
// under a parent with TPM2_Load
var oidLoadableKey = asn1.ObjectIdentifier{2, 23, 133, 10, 1, 3}

// tssKey is the TPM 2.0 key file's ASN.1 form, without the optional policy,
// secret and authPolicy fields. A key file holding any of them fails to parse
type tssKey struct {
	Type      asn1.ObjectIdentifier
	EmptyAuth bool `asn1:"explicit,tag:0,optional"`
	Parent    int64
	PubKey    []byte
	PrivKey   []byte
}

// srkTemplate is the template of the parent, the TCG's reference ECC P-256
// storage root key. The key file format assumes that parent for a key whose
// parent is a hierarchy
var srkTemplate = tpm2.ECCSRKTemplate

// withSRK runs f with the storage root key loaded, and flushes it after
func withSRK(t transport.TPM, f func(srk tpm2.AuthHandle) error) error {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		InPublic:      tpm2.New2B(srkTemplate),
	}.Execute(t)
	if err != nil {
		return fmt.Errorf("creating the TPM's storage root key: %w", err)
	}
	defer flush(t, rsp.ObjectHandle)
	return f(tpm2.AuthHandle{Handle: rsp.ObjectHandle, Name: rsp.Name, Auth: tpm2.PasswordAuth(nil)})
}

// flush frees a transient object. Its error is ignored, because the
// resource manager frees what a closed connection left anyway
func flush(t transport.TPM, h tpm2.TPMHandle) {
	_, _ = tpm2.FlushContext{FlushHandle: h}.Execute(t)
}

// loadTPM returns the key in a TPM key file's DER. The public area must be
// what createTSS (tpm_create.go) asks the TPM for, so a key file for a key
// the TPM would let out, or one that can decrypt, is refused
// The TPM itself checks the private area against the public one when it loads the key
func loadTPM(der []byte, openTPM tpmOpener) (*Key, error) {
	var tk tssKey
	rest, err := asn1.Unmarshal(der, &tk)
	if err != nil || len(rest) > 0 {
		return nil, errors.New("not a TPM 2.0 key file")
	}
	if !tk.Type.Equal(oidLoadableKey) || !tk.EmptyAuth || tk.Parent != int64(tpm2.TPMRHOwner) {
		return nil, errors.New("not a TPM key this endpoint made: a loadable key under the owner hierarchy, without a password")
	}
	pub, err := strictUnmarshal[tpm2.TPM2BPublic](tk.PubKey)
	if err != nil {
		return nil, fmt.Errorf("the TPM key's public area: %v", err)
	}
	priv, err := strictUnmarshal[tpm2.TPM2BPrivate](tk.PrivKey)
	if err != nil {
		return nil, fmt.Errorf("the TPM key's private area: %v", err)
	}
	ecPub, err := checkTPMPublic(pub)
	if err != nil {
		return nil, err
	}
	sign := func(digest []byte) ([]byte, error) {
		t, err := openTPM()
		if err != nil {
			return nil, err
		}
		defer t.Close()
		var sig []byte
		err = withSRK(t, func(srk tpm2.AuthHandle) error {
			lr, err := tpm2.Load{ParentHandle: srk, InPublic: *pub, InPrivate: *priv}.Execute(t)
			if err != nil {
				return fmt.Errorf("loading the key into the TPM (was it made by another TPM?): %w", err)
			}
			defer flush(t, lr.ObjectHandle)
			sr, err := tpm2.Sign{
				KeyHandle: tpm2.AuthHandle{Handle: lr.ObjectHandle, Name: lr.Name, Auth: tpm2.PasswordAuth(nil)},
				Digest:    tpm2.TPM2BDigest{Buffer: digest},
				InScheme: tpm2.TPMTSigScheme{
					Scheme:  tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
				},
				Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck, Hierarchy: tpm2.TPMRHNull},
			}.Execute(t)
			if err != nil {
				return fmt.Errorf("signing in the TPM: %w", err)
			}
			es, err := sr.Signature.Signature.ECDSA()
			if err != nil || sr.Signature.SigAlg != tpm2.TPMAlgECDSA || es.Hash != tpm2.TPMAlgSHA256 {
				return errors.New("the TPM didn't answer with an ECDSA SHA-256 signature")
			}
			sig, err = derSignature(ecPub, digest,
				new(big.Int).SetBytes(es.SignatureR.Buffer), new(big.Int).SetBytes(es.SignatureS.Buffer))
			return err
		})
		return sig, err
	}
	return &Key{Signer: &signerFunc{pub: ecPub, sign: sign}, Storage: TPM}, nil
}

// strictUnmarshal decodes a TPM structure that must take up all of data
func strictUnmarshal[T tpm2.Marshallable, P interface {
	*T
	tpm2.Unmarshallable
}](data []byte) (*T, error) {
	v, err := tpm2.Unmarshal[T, P](data)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(tpm2.Marshal(*v), data) {
		return nil, errors.New("trailing or non-canonical bytes")
	}
	return v, nil
}

// checkTPMPublic returns the key in a public area if the area is exactly
// what keyTemplate (tpm_create.go) asks for, apart from the point itself
func checkTPMPublic(b *tpm2.TPM2BPublic) (*ecdsa.PublicKey, error) {
	p, err := b.Contents()
	if err != nil {
		return nil, err
	}
	a := p.ObjectAttributes
	if p.Type != tpm2.TPMAlgECC || p.NameAlg != tpm2.TPMAlgSHA256 ||
		!a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin || !a.SignEncrypt ||
		a.Decrypt || a.Restricted || !a.UserWithAuth || a.AdminWithPolicy {
		return nil, errors.New("the TPM key is not a non-duplicable signing key generated in the TPM")
	}
	parms, err := p.Parameters.ECCDetail()
	if err != nil || parms.CurveID != tpm2.TPMECCNistP256 || parms.Scheme.Scheme != tpm2.TPMAlgECDSA {
		return nil, errors.New("the TPM key is not an ECDSA P-256 key")
	}
	if d, err := parms.Scheme.Details.ECDSA(); err != nil || d.HashAlg != tpm2.TPMAlgSHA256 {
		return nil, errors.New("the TPM key doesn't sign with SHA-256")
	}
	pt, err := p.Unique.ECC()
	if err != nil {
		return nil, err
	}
	pub, err := tpm2.ECDSAPub(parms, pt)
	if err != nil || pub.Curve != elliptic.P256() {
		return nil, errors.New("the TPM key is not an ECDSA P-256 key")
	}
	if _, err := pub.ECDH(); err != nil {
		return nil, errors.New("the TPM key's public point is not on P-256")
	}
	return pub, nil
}
