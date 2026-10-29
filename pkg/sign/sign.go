// Package sign signs and verifies policy files with ed25519.
//
// The private key stays with whoever publishes policies.
// Endpoints and the console hold only the public key.
//
// A signature covers the policy's name, the SHA-256 of its exact bytes, a
// serial and an expiry. A signed policy therefore cannot be edited, truncated
// or served under another name. An endpoint does not install a policy whose
// serial is lower than the one it has (a rollback). A policy with an expiry is
// no longer trusted after that time.
//
// Keys are PEM encoded (PKCS #8 for private keys, PKIX for public keys).
// The signature is a POLICY.sig file next to the policy.
// The format is part of docs/protocol.
package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"

	"cyberboar.dev/cyberboar/internal/atomicfile"
	"cyberboar.dev/cyberboar/internal/boundedfile"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// SigSuffix is appended to a policy file's path for its signature.
const SigSuffix = ".sig"

// MaxSerial is the largest serial.
// It is the largest value of a signed 64-bit integer.
const MaxSerial = 1<<63 - 1

// TimeFormat is the form of an expiry, which is RFC 3339 in UTC with whole seconds.
const TimeFormat = "2006-01-02T15:04:05Z"

// maxSig bounds a signature file.
const maxSig = 256

// maxKey bounds PEM input; an ed25519 key block is less than 256 bytes.
const maxKey = 4 << 10

// signatureTag begins both the signed message and the signature file.
const signatureTag = brand.APIGroup + "/policy-signature/v2"

// Header is what a signature asserts besides the policy's name and bytes.
type Header struct {
	// Serial orders the signatures of one deployment.
	// An endpoint never installs a lower serial than the one it has.
	Serial uint64
	// Expires is when endpoints stop trusting the policy - from then on the hook denies every call.
	// The zero time means the policy never expires.
	Expires time.Time
}

// Expired reports whether the policy has expired at now.
// The expiry instant itself is expired, and a policy without expiry never is.
func (h Header) Expired(now time.Time) bool { return !h.Expires.IsZero() && !now.Before(h.Expires) }

// Expiry returns the expiry as signed, in TimeFormat in UTC or as "never".
func (h Header) Expiry() string {
	if h.Expires.IsZero() {
		return never
	}
	return h.Expires.UTC().Format(TimeFormat)
}

const never = "never"

func (h Header) check() error {
	if h.Serial < 1 || h.Serial > MaxSerial {
		return fmt.Errorf("serial %d is outside 1..%d", h.Serial, uint64(MaxSerial))
	}
	if !h.Expires.IsZero() && (!h.Expires.Equal(h.Expires.Truncate(time.Second)) || h.Expires.Unix() <= 0 || h.Expires.UTC().Year() > 9999) {
		return fmt.Errorf("expiry %s is not whole seconds after 1970 and before the year 10000", h.Expires)
	}
	return nil
}

// message returns what is signed, which is a domain separator, the policy
// name, the SHA-256 of the policy file, the serial and the expiry.
func message(name string, policy []byte, h Header) []byte {
	sum := sha256.Sum256(policy)
	return []byte(signatureTag + "\n" + name + "\n" + hex.EncodeToString(sum[:]) + "\n" +
		strconv.FormatUint(h.Serial, 10) + "\n" + h.Expiry() + "\n")
}

// Keygen writes a new ed25519 key pair, the private key to privPath with mode
// 0600 on POSIX (a protected owner/SYSTEM DACL on Windows) and the public key
// to pubPath.
// Neither file may exist yet, so that a key is never replaced and a pair never
// ends up mismatched.
// An existing file fails with an error that matches fs.ErrExist.
// When Keygen fails, it leaves no file of its own behind.
func Keygen(privPath, pubPath string) error {
	for _, p := range []string{privPath, pubPath} {
		if _, err := os.Lstat(p); err == nil {
			return &fs.PathError{Op: "create", Path: p, Err: fs.ErrExist}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	// WriteNew creates each file only if it is still missing, so a key that
	// appeared since the check above is not replaced either
	if err := writePrivate(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})); err != nil {
		return err
	}
	if err := atomicfile.WriteNew(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		// The private key was created just now
		// It is of no use without its public key, and left in place it would break the next Keygens
		os.Remove(privPath)
		return err
	}
	return nil
}

func readPEM(path, typ string) ([]byte, error) {
	data, err := boundedfile.Read(path, maxKey)
	if err != nil {
		return nil, err
	}
	b, rest := pem.Decode(data)
	if b == nil || b.Type != typ || len(strings.TrimSpace(string(rest))) > 0 {
		return nil, fmt.Errorf("%s: not a single PEM %q block", path, typ)
	}
	return b.Bytes, nil
}

// LoadPrivate reads an ed25519 private key.
func LoadPrivate(path string) (ed25519.PrivateKey, error) {
	der, err := readPEM(path, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an ed25519 key", path)
	}
	return priv, nil
}

// LoadPublic reads an ed25519 public key.
func LoadPublic(path string) (ed25519.PublicKey, error) {
	der, err := readPEM(path, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an ed25519 key", path)
	}
	return pub, nil
}

// Sign returns the signature file contents for a policy named name.
func Sign(priv ed25519.PrivateKey, name string, policy []byte, h Header) (string, error) {
	if err := h.check(); err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, message(name, policy, h))
	return signatureTag + "\nserial " + strconv.FormatUint(h.Serial, 10) + "\nexpires " + h.Expiry() +
		"\nsignature " + base64.StdEncoding.EncodeToString(sig) + "\n", nil
}

// ErrBadSignature means the signature doesn't match the policy and key, or isn't a signature file.
var ErrBadSignature = errors.New("the policy signature is not valid for this key")

// Parse reads a signature file's header without verifying anything.
// Only the exact form Sign writes is accepted.
func Parse(sig []byte) (Header, []byte, error) {
	if len(sig) > maxSig {
		return Header{}, nil, ErrBadSignature
	}
	lines := strings.Split(string(sig), "\n")
	if len(lines) != 5 || lines[0] != signatureTag || lines[4] != "" {
		return Header{}, nil, ErrBadSignature
	}
	serial, ok1 := strings.CutPrefix(lines[1], "serial ")
	expires, ok2 := strings.CutPrefix(lines[2], "expires ")
	b64, ok3 := strings.CutPrefix(lines[3], "signature ")
	if !ok1 || !ok2 || !ok3 {
		return Header{}, nil, ErrBadSignature
	}
	var h Header
	var err error
	if h.Serial, err = strconv.ParseUint(serial, 10, 64); err != nil || strconv.FormatUint(h.Serial, 10) != serial {
		return Header{}, nil, ErrBadSignature
	}
	if expires != never {
		if h.Expires, err = time.Parse(TimeFormat, expires); err != nil || h.Expires.Format(TimeFormat) != expires {
			return Header{}, nil, ErrBadSignature
		}
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil || len(raw) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(raw) != b64 || h.check() != nil {
		return Header{}, nil, ErrBadSignature
	}
	return h, raw, nil
}

// Verify checks sig (signature file contents) against the policy and returns its header.
// Callers decide what an expired policy means.
func Verify(pub ed25519.PublicKey, name string, policy []byte, sig []byte) (Header, error) {
	if len(pub) != ed25519.PublicKeySize {
		return Header{}, ErrBadSignature // ed25519.Verify would panic
	}
	h, raw, err := Parse(sig)
	if err != nil {
		return Header{}, err
	}
	if !ed25519.Verify(pub, message(name, policy, h), raw) {
		return Header{}, ErrBadSignature
	}
	return h, nil
}

// ReadSig reads the signature file next to a policy, bounded.
func ReadSig(policyPath string) ([]byte, error) {
	return boundedfile.Read(policyPath+SigSuffix, maxSig+1)
}
