// Package endpointauth implements how endpoints and consoles authenticate
// each other (docs/protocol, "Endpoint authentication").
//
// An endpoint holds an ECDSA P-256 key it created when it enrolled. The
// console holds the public half and issues a short-lived client certificate
// for it. Every request an endpoint sends is signed with HTTP Message
// Signatures (RFC 9421) in one fixed profile. The signature covers the
// method, path, query and body digest (RFC 9530 Content-Digest), with the
// signing time, a random nonce and the endpoint ID as parameters. Every
// answer a console sends to an enrolled endpoint is signed the same way with
// the console's key, which the endpoint pinned at enrollment, and covers the
// status, the body digest and the request's own signature, so an answer
// can't be replayed for another request.
//
// Verifiers accept the profile byte for byte and nothing else, so there is
// no algorithm, component list or encoding for a peer to choose. The
// signatures cover the messages, not the TLS connection, so they hold
// through a proxy or ingress that terminates TLS. The scheme and authority
// are not covered for the same reason. A proxy that rewrites the path breaks
// every signature.
//
// Signer and VerifyResponse are the endpoint's half, and ParseRequest and
// ResponseSigner are the console's.
package endpointauth

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"cyberboar.dev/cyberboar/pkg/brand"
)

// Algorithm is the only signature algorithm (RFC 9421 §3.3.4), and the alg parameter's value.
const Algorithm = "ecdsa-p256-sha256"

// MaxSkew is how far a signature's created time may be from the verifier's clock.
// A captured request can't be replayed later than this, and within it the nonce can't be used twice.
const MaxSkew = 5 * time.Minute

// Paths of the requests this package's messages belong to.
const (
	EnrollPath      = "/api/v1/enroll"
	CertificatePath = "/api/v1/endpoint/certificate"
)

// label names the one signature in Signature-Input and Signature.
// The tags say what a signature is for, so neither side's signature can be taken
// for the other's, or for another application's.
const (
	label       = brand.Name
	requestTag  = brand.APIGroup + "/endpoint/v1"
	responseTag = brand.APIGroup + "/console/v1"
)

// The covered component lists.
// A request without a body covers the digest of no bytes.
const (
	requestComponents  = `("@method" "@path" "@query" "content-digest")`
	responseComponents = `("@status" "content-digest" "signature";req;key="` + label + `")`
)

// Header patterns of the profile.
// Anything else, including other valid RFC 9421 forms, is rejected.
var (
	requestInputRE = regexp.MustCompile(`^` + regexp.QuoteMeta(label+"="+requestComponents) +
		`;created=([0-9]{1,15});keyid="([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})"` +
		`;nonce="([A-Za-z0-9_-]{22})"` + regexp.QuoteMeta(`;alg="`+Algorithm+`";tag="`+requestTag+`"`) + `$`)
	responseInputRE = regexp.MustCompile(`^` + regexp.QuoteMeta(label+"="+responseComponents) +
		`;created=([0-9]{1,15});keyid="([0-9a-f]{64})"` + regexp.QuoteMeta(`;alg="`+Algorithm+`";tag="`+responseTag+`"`) + `$`)
	signatureRE = regexp.MustCompile(`^` + regexp.QuoteMeta(label) + `=(:[A-Za-z0-9+/]{86}==:)$`)
	digestRE    = regexp.MustCompile(`^sha-256=:([A-Za-z0-9+/]{43}=):$`)
	uuidRE      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// ValidEndpointID reports whether s is an endpoint ID, which is a lowercase version 4 UUID.
func ValidEndpointID(s string) bool { return uuidRE.MatchString(s) }

func requestParams(created int64, keyID, nonce string) string {
	return requestComponents + ";created=" + strconv.FormatInt(created, 10) + `;keyid="` + keyID + `";nonce="` + nonce +
		`";alg="` + Algorithm + `";tag="` + requestTag + `"`
}

func responseParams(created int64, keyID string) string {
	return responseComponents + ";created=" + strconv.FormatInt(created, 10) + `;keyid="` + keyID +
		`";alg="` + Algorithm + `";tag="` + responseTag + `"`
}

// requestBase builds a request's signature base (RFC 9421 §2.5).
func requestBase(method string, u *url.URL, digest, params string) ([]byte, error) {
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	query := "?" + u.RawQuery
	for _, v := range []string{method, path, query} {
		// A line break in a component would let one component pose as another
		// net/http refuses them already, but this doesn't rely on it
		for i := 0; i < len(v); i++ {
			if v[i] < 0x21 || v[i] > 0x7e {
				return nil, errors.New("the request line has a character a signature can't cover")
			}
		}
	}
	return []byte(`"@method": ` + method + "\n" +
		`"@path": ` + path + "\n" +
		`"@query": ` + query + "\n" +
		`"content-digest": ` + digest + "\n" +
		`"@signature-params": ` + params), nil
}

// responseBase builds an answer's signature base
// requestSig is the request's signature as its Signature field's member value.
func responseBase(status int, digest, requestSig, params string) []byte {
	return []byte(`"@status": ` + strconv.Itoa(status) + "\n" +
		`"content-digest": ` + digest + "\n" +
		`"signature";req;key="` + label + `": ` + requestSig + "\n" +
		`"@signature-params": ` + params)
}

// ContentDigest returns the Content-Digest field value (RFC 9530) for body.
func ContentDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// checkDigest checks a Content-Digest field value against body.
func checkDigest(field string, body []byte) bool {
	m := digestRE.FindStringSubmatch(field)
	if m == nil {
		return false
	}
	want, err := base64.StdEncoding.Strict().DecodeString(m[1])
	if err != nil {
		return false
	}
	sum := sha256.Sum256(body)
	return subtle.ConstantTimeCompare(sum[:], want) == 1
}

// p256 returns pub as a P-256 key, or nil.
func p256(pub crypto.PublicKey) *ecdsa.PublicKey {
	k, ok := pub.(*ecdsa.PublicKey)
	if !ok || k == nil || k.Curve != elliptic.P256() {
		return nil
	}
	return k
}

// signBase signs base with key and returns the signature in RFC 9421's form
// for ECDSA, r and s as 32-byte big-endian integers, base64-encoded.
func signBase(key crypto.Signer, base []byte) (string, error) {
	if p256(key.Public()) == nil {
		return "", errors.New("the key is not an ECDSA P-256 key")
	}
	sum := sha256.Sum256(base)
	der, err := key.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	var rs struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &rs); err != nil || len(rest) > 0 ||
		rs.R.Sign() <= 0 || rs.S.Sign() <= 0 || rs.R.BitLen() > 256 || rs.S.BitLen() > 256 {
		return "", errors.New("the key returned a malformed ECDSA signature")
	}
	var raw [64]byte
	rs.R.FillBytes(raw[:32])
	rs.S.FillBytes(raw[32:])
	return ":" + base64.StdEncoding.EncodeToString(raw[:]) + ":", nil
}

// verifyBase checks a signature in signBase's form. ecdsa.Verify rejects r and s outside [1, n-1].
func verifyBase(pub *ecdsa.PublicKey, base []byte, sig string) bool {
	raw, err := base64.StdEncoding.Strict().DecodeString(sig[1 : len(sig)-1])
	if err != nil || len(raw) != 64 || pub == nil {
		return false
	}
	sum := sha256.Sum256(base)
	return ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:]))
}

// Signer signs an enrolled endpoint's requests.
type Signer struct {
	ID  string           // endpoint ID, which is the signature's keyid
	Key crypto.Signer    // the endpoint's P-256 key
	Now func() time.Time // the clock, time.Now if nil
}

// Sign sets req's Content-Digest, Signature-Input and Signature headers
// body is the request body, nil for none, and req must send exactly those bytes.
// Every call uses a new nonce, so a retry is a new request.
func (s *Signer) Sign(req *http.Request, body []byte) error {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	var n [16]byte
	rand.Read(n[:]) // never fails (crypto/rand)
	return s.sign(req, body, now().Unix(), base64.RawURLEncoding.EncodeToString(n[:]))
}

func (s *Signer) sign(req *http.Request, body []byte, created int64, nonce string) error {
	if !ValidEndpointID(s.ID) || s.Key == nil {
		return errors.New("the endpoint ID or key is invalid")
	}
	params := requestParams(created, s.ID, nonce)
	digest := ContentDigest(body)
	base, err := requestBase(req.Method, req.URL, digest, params)
	if err != nil {
		return err
	}
	sig, err := signBase(s.Key, base)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Digest", digest)
	req.Header.Set("Signature-Input", label+"="+params)
	req.Header.Set("Signature", label+"="+sig)
	return nil
}

// Request is a request's signature, parsed and within the time window but not yet verified.
type Request struct {
	EndpointID string    // the endpoint the signature names
	Created    time.Time // the signature's created time
	Nonce      string    // the signature's nonce, as the endpoint chose it
	digest     string    // the Content-Digest field
	base       []byte
	sig        string // the Signature member value, the base64 between colons
}

// ParseRequest reads r's signature headers and checks everything that needs
// neither the key nor the body, which is the profile, the endpoint ID's form
// and the time window
// now is the console's clock.
func ParseRequest(r *http.Request, now time.Time) (*Request, error) {
	inputs, sigs, digests := r.Header.Values("Signature-Input"), r.Header.Values("Signature"), r.Header.Values("Content-Digest")
	if len(inputs) == 0 && len(sigs) == 0 {
		return nil, unauthenticated("the request is not signed: enroll this endpoint with `%s enroll`", brand.Name)
	}
	if len(inputs) != 1 || len(sigs) != 1 || len(digests) != 1 {
		return nil, unauthenticated("the request needs exactly one Signature-Input, Signature and Content-Digest header")
	}
	m := requestInputRE.FindStringSubmatch(inputs[0])
	if m == nil {
		return nil, unauthenticated("Signature-Input is not the %s endpoint profile", brand.DisplayName)
	}
	created, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return nil, unauthenticated("Signature-Input has an invalid created time")
	}
	params := requestParams(created, m[2], m[3])
	if label+"="+params != inputs[0] {
		return nil, unauthenticated("Signature-Input is not in canonical form") // e.g. leading zeros
	}
	sm := signatureRE.FindStringSubmatch(sigs[0])
	if sm == nil {
		return nil, unauthenticated("Signature is not one %s signature labeled %q", Algorithm, label)
	}
	if !digestRE.MatchString(digests[0]) {
		return nil, unauthenticated("Content-Digest must be one sha-256 digest")
	}
	t := time.Unix(created, 0)
	if t.Before(now.Add(-MaxSkew)) || t.After(now.Add(MaxSkew)) {
		return nil, &Error{Status: http.StatusUnauthorized, Code: CodeStale, Message: fmt.Sprintf(
			"the request was signed at %s, more than %s from the console's clock (%s): check the endpoint's clock",
			t.UTC().Format(time.RFC3339), MaxSkew, now.UTC().Format(time.RFC3339))}
	}
	base, err := requestBase(r.Method, r.URL, digests[0], params)
	if err != nil {
		return nil, unauthenticated("%v", err)
	}
	return &Request{EndpointID: m[2], Created: t, Nonce: m[3], digest: digests[0], base: base, sig: sm[1]}, nil
}

// Verify checks the signature against the endpoint's public key.
func (q *Request) Verify(pub *ecdsa.PublicKey) error {
	if !verifyBase(p256(pub), q.base, q.sig) {
		return unauthenticated("the request's signature doesn't verify with this endpoint's key")
	}
	return nil
}

// CheckBody checks that body is what the signed Content-Digest describes.
func (q *Request) CheckBody(body []byte) error {
	if !checkDigest(q.digest, body) {
		return unauthenticated("the request body doesn't match its signed Content-Digest")
	}
	return nil
}

// NonceExpires is the last time at which ParseRequest accepts the request.
// ParseRequest rejects it as stale only once the console's clock is after
// NonceExpires, so the console must remember the request's nonce until then,
// that instant included.
// It may forget the nonce only when its clock is after NonceExpires.
func (q *Request) NonceExpires() time.Time { return q.Created.Add(MaxSkew) }

// ResponseSigner signs a console's answers to enrolled endpoints.
type ResponseSigner struct {
	Key crypto.Signer    // the console's P-256 key
	Now func() time.Time // the clock, time.Now if nil
}

// Sign sets the Content-Digest, Signature-Input and Signature headers of an
// answer to q with this status and body.
func (s *ResponseSigner) Sign(h http.Header, status int, body []byte, q *Request) error {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	return s.sign(h, status, body, q.sig, now().Unix())
}

func (s *ResponseSigner) sign(h http.Header, status int, body []byte, requestSig string, created int64) error {
	var pub *ecdsa.PublicKey
	if s.Key != nil {
		pub = p256(s.Key.Public())
	}
	if pub == nil {
		return errors.New("the console key is not an ECDSA P-256 key")
	}
	params := responseParams(created, KeyID(pub))
	digest := ContentDigest(body)
	sig, err := signBase(s.Key, responseBase(status, digest, requestSig, params))
	if err != nil {
		return err
	}
	h.Set("Content-Digest", digest)
	h.Set("Signature-Input", label+"="+params)
	h.Set("Signature", label+"="+sig)
	return nil
}

// VerifyResponse checks that resp, whose body is body, is the console's answer
// to req, the request as Signer signed it
// The answer must be signed with the console's pinned key, within MaxSkew of now,
// over its status and body. An endpoint acts on no answer below 400 that fails this.
func VerifyResponse(resp *http.Response, body []byte, req *http.Request, console *ecdsa.PublicKey, now time.Time) error {
	rm := signatureRE.FindStringSubmatch(req.Header.Get("Signature"))
	if rm == nil {
		return errors.New("the request was not signed")
	}
	inputs, sigs, digests := resp.Header.Values("Signature-Input"), resp.Header.Values("Signature"), resp.Header.Values("Content-Digest")
	if len(inputs) == 0 && len(sigs) == 0 {
		return errors.New("the answer is not signed")
	}
	if len(inputs) != 1 || len(sigs) != 1 || len(digests) != 1 {
		return errors.New("the answer needs exactly one Signature-Input, Signature and Content-Digest header")
	}
	m := responseInputRE.FindStringSubmatch(inputs[0])
	if m == nil {
		return fmt.Errorf("the answer's Signature-Input is not the %s console profile", brand.DisplayName)
	}
	created, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil || label+"="+responseParams(created, m[2]) != inputs[0] {
		return errors.New("the answer's Signature-Input is not in canonical form")
	}
	pub := p256(console)
	if pub == nil || m[2] != KeyID(pub) {
		return errors.New("the answer is signed with a key other than the console's pinned key")
	}
	sm := signatureRE.FindStringSubmatch(sigs[0])
	if sm == nil {
		return errors.New("the answer's Signature is not one signature in the profile")
	}
	if t := time.Unix(created, 0); t.Before(now.Add(-MaxSkew)) || t.After(now.Add(MaxSkew)) {
		return fmt.Errorf("the answer was signed at %s, more than %s from this machine's clock (%s): check the clock",
			t.UTC().Format(time.RFC3339), MaxSkew, now.UTC().Format(time.RFC3339))
	}
	if !checkDigest(digests[0], body) {
		return errors.New("the answer's body doesn't match its Content-Digest")
	}
	if !verifyBase(pub, responseBase(resp.StatusCode, digests[0], rm[1], responseParams(created, m[2])), sm[1]) {
		return errors.New("the answer's signature doesn't verify with the console's pinned key, or answers another request")
	}
	return nil
}

// KeyID returns the keyid by which a console's answers name its key.
// It is the lowercase hex SHA-256 of the key's PKIX (SubjectPublicKeyInfo) encoding.
func KeyID(pub *ecdsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// EncodePublicKey returns a P-256 public key as the protocol carries it, in
// standard base64 of its PKIX (SubjectPublicKeyInfo) encoding.
func EncodePublicKey(pub *ecdsa.PublicKey) (string, error) {
	if p256(pub) == nil {
		return "", errors.New("not an ECDSA P-256 key")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// DecodePublicKey reads a key only in EncodePublicKey's form.
func DecodePublicKey(s string) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, errors.New("the key is not valid base64")
	}
	if base64.StdEncoding.EncodeToString(der) != s {
		return nil, errors.New("the key is not in its canonical encoding")
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("the key is not a PKIX public key: %w", err)
	}
	pub := p256(k)
	if pub == nil {
		return nil, errors.New("the key is not an ECDSA P-256 key")
	}
	if again, _ := x509.MarshalPKIXPublicKey(pub); !bytes.Equal(again, der) {
		return nil, errors.New("the key is not in its canonical encoding")
	}
	return pub, nil
}
