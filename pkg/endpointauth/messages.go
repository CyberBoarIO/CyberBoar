package endpointauth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"time"

	"cyberboar.dev/cyberboar/pkg/audit"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// These are the error codes a console answers with, as docs/protocol lists them under "Errors".
// Endpoints only show them.
// No code makes an endpoint do anything but keep its state and report.
const (
	CodeUnauthenticated = "unauthenticated" // no valid signature from a known endpoint
	CodeStale           = "stale"           // created is more than MaxSkew from the console's clock
	CodeReplayed        = "replayed"        // the nonce was seen before
	CodeCertificate     = "certificate"     // no client certificate, or not this endpoint's
	CodeRevoked         = "revoked"         // the endpoint was revoked and must enroll as a new one
	CodeForbidden       = "forbidden"       // authenticated, but not allowed this
	CodeToken           = "token"           // the enrollment token is unknown, expired, revoked or used up
	CodeConflict        = "conflict"        // the endpoint ID is enrolled with another key, or was revoked
)

// Error is a refusal.
// It holds the HTTP status, the protocol's error code and a message that is safe to send to the client.
// Messages say what to fix without telling an unauthenticated client whether an endpoint exists.
type Error struct {
	Status  int
	Code    string
	Message string
}

// Error returns the message, the part of the refusal that is sent to the client.
func (e *Error) Error() string { return e.Message }

func unauthenticated(format string, args ...any) error {
	return &Error{Status: http.StatusUnauthorized, Code: CodeUnauthenticated, Message: fmt.Sprintf(format, args...)}
}

// ErrorResponse is the body of an error answer.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// EnrollRequest is the body of POST EnrollPath.
// The request is signed with the key it enrolls.
type EnrollRequest struct {
	Token     string         `json:"token"`
	Endpoint  audit.Endpoint `json:"endpoint"`
	PublicKey string         `json:"publicKey"` // EncodePublicKey
}

// EnrollResponse is the console's answer to an enrollment, signed with the key it names.
type EnrollResponse struct {
	EndpointID  string `json:"endpointId"`
	Policy      string `json:"policy"`      // the policy (metadata.name) the console assigned
	Certificate string `json:"certificate"` // PEM, the client certificate first, then intermediates
	ConsoleKey  string `json:"consoleKey"`  // EncodePublicKey of the key that signs the console's answers
}

// CertificateResponse is the console's answer to POST CertificatePath.
// It holds a new client certificate for the same key.
type CertificateResponse struct {
	Certificate string `json:"certificate"` // as in EnrollResponse
}

// TokenPrefix starts every enrollment token, so secret scanners can find leaked ones.
const TokenPrefix = brand.Name + "_enroll_"

var tokenRE = regexp.MustCompile(`^` + regexp.QuoteMeta(TokenPrefix) + `[A-Za-z0-9_-]{43}$`)

// NewToken returns a new enrollment token and the hash a console keeps.
// The token itself is shown once and never stored.
func NewToken() (token string, hash []byte) {
	var b [32]byte
	rand.Read(b[:]) // never fails (crypto/rand)
	token = TokenPrefix + base64.RawURLEncoding.EncodeToString(b[:])
	return token, HashToken(token)
}

// ValidToken reports whether it has the form of an enrollment token.
func ValidToken(s string) bool { return tokenRE.MatchString(s) }

// HashToken returns the hash under which a console stores a token.
// A token has 256 random bits, so a plain SHA-256 can't be reversed by search.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

var policyNameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// ValidPolicyName reports whether it is a policy name (metadata.name, a DNS label).
func ValidPolicyName(s string) bool { return policyNameRE.MatchString(s) }

// EndpointURI is the one URI subject alternative name of an endpoint's client certificate.
func EndpointURI(id string) string { return "urn:uuid:" + id }

// MaxCertificatePEM bounds a certificate chain in an answer.
const MaxCertificatePEM = 16 << 10

// MatchCertificate checks that a client certificate is the endpoint's, which
// means its one URI name is EndpointURI(id) and it holds pub.
// A console checks this for the certificate a request came with, against the endpoint
// the request is signed by.
func MatchCertificate(cert *x509.Certificate, id string, pub *ecdsa.PublicKey) error {
	if len(cert.URIs) != 1 || cert.URIs[0].String() != EndpointURI(id) {
		return fmt.Errorf("the client certificate doesn't name endpoint %s", id)
	}
	k, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub == nil || !k.Equal(pub) {
		return errors.New("the client certificate is not for this endpoint's key")
	}
	return nil
}

// CheckCertificate parses a PEM certificate chain a console issued and
// checks that the client certificate, the first, is for this endpoint and
// key (MatchCertificate), is valid at now and is for client authentication.
// The endpoint doesn't verify the chain itself, because it only presents it
// and the console verifies it.
func CheckCertificate(chainPEM []byte, id string, pub *ecdsa.PublicKey, now time.Time) ([]*x509.Certificate, error) {
	if len(chainPEM) > MaxCertificatePEM {
		return nil, fmt.Errorf("the certificate chain is larger than %d bytes", MaxCertificatePEM)
	}
	var chain []*x509.Certificate
	for rest := chainPEM; len(bytes.TrimSpace(rest)) > 0; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) > 0 {
			return nil, errors.New("the certificate chain is not a series of PEM CERTIFICATE blocks")
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("the certificate chain: %w", err)
		}
		chain = append(chain, c)
	}
	if len(chain) == 0 || len(chain) > 4 {
		return nil, errors.New("the certificate chain must hold the client certificate and at most three intermediates")
	}
	leaf := chain[0]
	if err := MatchCertificate(leaf, id, pub); err != nil {
		return nil, err
	}
	switch {
	case leaf.IsCA:
		return nil, errors.New("the client certificate is a CA certificate")
	case !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth):
		return nil, errors.New("the client certificate is not for client authentication")
	case now.Before(leaf.NotBefore.Add(-MaxSkew)) || !now.Before(leaf.NotAfter):
		return nil, fmt.Errorf("the client certificate is valid from %s to %s, not now (%s)",
			leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return chain, nil
}
