// Package protocoltest is a minimal console for the core's tests. It enrolls
// endpoints, serves policy bundles and accepts audit events as docs/protocol
// specifies, over TLS 1.3 only, and does nothing else. Every request is
// checked as docs/protocol lists it, with mutual TLS and a signed request,
// and every answer below 400 is signed. NewStatic is a static bundle host
// instead, without authentication. The real console lives in its own
// repository, and both are checked against the golden files in
// testdata/protocol.
package protocoltest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"cyberboar.dev/cyberboar/pkg/audit"
	"cyberboar.dev/cyberboar/pkg/bundle"
	"cyberboar.dev/cyberboar/pkg/endpointauth"
)

// Limits from docs/protocol.
const (
	maxBodyBytes   = 4 << 20
	maxBatchEvents = 1000
	maxEnrollBody  = 4 << 10
	maxLabel       = 255
)

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Endpoint is an enrolled endpoint as the console knows it.
type Endpoint struct {
	ID       string
	Hostname string
	Policy   string
	Key      *ecdsa.PublicKey
	Revoked  bool
}

type token struct {
	policy  string
	uses    int
	expires time.Time
	revoked bool
}

// Console is a running test console.
type Console struct {
	*httptest.Server
	dir    string
	pub    ed25519.PublicKey
	static bool

	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey

	mu           sync.Mutex
	key          *ecdsa.PrivateKey // signs the console's answers; endpoints pin its public half
	certValidity time.Duration     // of the client certificates it issues
	dropAnswer   bool              // the next new enrollment is recorded, then its connection is dropped
	now          func() time.Time
	set          *bundle.Set
	batches      []audit.Batch
	tokens       map[string]*token // by hex SHA-256
	endpoints    map[string]*Endpoint
	nonces       map[string]time.Time // when each "id nonce" may be forgotten
	refusals     []string             // error codes sent, in order
}

// New starts a console serving the policies in dir. With pub set, only
// policies signed with that key are served, as a console configured with
// a key does.
func New(t testing.TB, dir string, pub ed25519.PublicKey) *Console {
	t.Helper()
	c := newConsole(t, dir, pub)
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+endpointauth.EnrollPath, c.enroll)
	mux.HandleFunc("POST "+endpointauth.CertificatePath, c.renew)
	mux.HandleFunc("GET /api/v1/bundles/{name}", c.bundle)
	mux.HandleFunc("POST /api/v1/events", c.ingest)
	c.start(t, mux)
	return c
}

// NewStatic starts a static bundle host. It serves the bundles in dir as
// `bundle` writes them for any web server, without authentication.
func NewStatic(t testing.TB, dir string, pub ed25519.PublicKey) *Console {
	t.Helper()
	c := newConsole(t, dir, pub)
	c.static = true
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/bundles/{name}", c.bundle)
	c.start(t, mux)
	return c
}

func newConsole(t testing.TB, dir string, pub ed25519.PublicKey) *Console {
	c := &Console{dir: dir, pub: pub, certValidity: 30 * 24 * time.Hour, now: time.Now,
		tokens: map[string]*token{}, endpoints: map[string]*Endpoint{}, nonces: map[string]time.Time{}}
	if dir != "" {
		c.Reload(t)
	}
	var err error
	if c.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if c.caKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "protocoltest endpoint CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &c.caKey.PublicKey, c.caKey)
	if err != nil {
		t.Fatal(err)
	}
	c.ca, _ = x509.ParseCertificate(der)
	return c
}

func (c *Console) start(t testing.TB, h http.Handler) {
	c.Server = httptest.NewUnstartedServer(h)
	c.Server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	if !c.static {
		// Enrollment comes without a certificate, so a certificate is asked
		// for, not required. authenticate requires it on every other request.
		pool := x509.NewCertPool()
		pool.AddCert(c.ca)
		c.Server.TLS.ClientAuth = tls.VerifyClientCertIfGiven
		c.Server.TLS.ClientCAs = pool
		c.Server.TLS.Time = c.clock
	}
	c.StartTLS()
	t.Cleanup(c.Close)
}

// CAFile writes a PEM file that makes a client trust this console's
// certificate (the --ca flag), and returns its path.
func (c *Console) CAFile(t testing.TB) string {
	t.Helper()
	return CAFile(t, c.Server)
}

// CAFile writes the certificate of a TLS test server to a PEM file and
// returns its path.
func CAFile(t testing.TB, srv *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// clock returns the console's time.
func (c *Console) clock() time.Time {
	c.mu.Lock()
	now := c.now
	c.mu.Unlock()
	return now()
}

// SetClock sets the console's clock, which it checks signatures, tokens and
// client certificates against and issues certificates from.
func (c *Console) SetClock(now func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

// SetCertValidity sets how long the client certificates it issues last.
func (c *Console) SetCertValidity(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.certValidity = d
}

// DropNextEnrollmentAnswer makes the console close the connection, without
// answering, right after it records the next new enrollment. The endpoint is
// then enrolled, but its answer is lost on the way.
func (c *Console) DropNextEnrollmentAnswer() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dropAnswer = true
}

// ConsoleKey returns the public key the console's answers are signed with.
func (c *Console) ConsoleKey() *ecdsa.PublicKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	return &c.key.PublicKey
}

// ReplaceKey makes the console sign its answers with a new key, which no
// endpoint has pinned.
func (c *Console) ReplaceKey(t testing.TB) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.key = k
}

// ConsoleKeyFile writes ConsoleKey as a PEM file (the --console-key flag)
// and returns its path.
func (c *Console) ConsoleKeyFile(t testing.TB) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(c.ConsoleKey())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "console.pub")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Token creates an enrollment token for policy that enrolls up to uses
// endpoints within an hour, and returns it.
func (c *Console) Token(policy string, uses int) string {
	tok, hash := endpointauth.NewToken()
	expires := c.clock().Add(time.Hour)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokens[hex.EncodeToString(hash)] = &token{policy: policy, uses: uses, expires: expires}
	return tok
}

// Revoke revokes an enrolled endpoint.
func (c *Console) Revoke(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.endpoints[id]; e != nil {
		e.Revoked = true
	}
}

// Assign changes the policy an enrolled endpoint gets.
func (c *Console) Assign(id, policy string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.endpoints[id]; e != nil {
		e.Policy = policy
	}
}

// Endpoints returns the enrolled endpoints.
func (c *Console) Endpoints() []Endpoint {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Endpoint
	for _, e := range c.endpoints {
		out = append(out, *e)
	}
	return out
}

// Refusals returns the error codes the console answered with, in order.
func (c *Console) Refusals() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.refusals...)
}

// Reload rereads the policy directory.
func (c *Console) Reload(t testing.TB) {
	t.Helper()
	set, err := bundle.LoadDir(c.dir, c.pub)
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.set = set
	c.mu.Unlock()
}

// Batches returns the accepted event batches.
func (c *Console) Batches() []audit.Batch {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]audit.Batch(nil), c.batches...)
}

func (c *Console) bundle(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var q *endpointauth.Request
	if !c.static {
		var ep *Endpoint
		var err error
		if q, ep, err = c.authenticate(r, nil, false); err != nil {
			c.fail(w, err)
			return
		}
		if name != ep.Policy {
			c.fail(w, &endpointauth.Error{Status: http.StatusForbidden, Code: endpointauth.CodeForbidden,
				Message: fmt.Sprintf("policy %q is not assigned to this endpoint", name)})
			return
		}
	}
	c.mu.Lock()
	b, ok := c.set.Bundle(name)
	c.mu.Unlock()
	if !ok {
		http.Error(w, "no such bundle", http.StatusNotFound)
		return
	}
	w.Header().Set("ETag", b.ETag)
	if etagMatches(r.Header.Get("If-None-Match"), b.ETag) {
		c.answer(w, q, http.StatusNotModified, nil)
		return
	}
	c.answer(w, q, http.StatusOK, b.Body)
}

// checkJSON refuses a body that isn't application/json with 415. A browser
// can't send application/json cross-origin without a CORS preflight.
func checkJSON(r *http.Request) error {
	mt, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" || len(params) > 1 ||
		len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8") {
		return &endpointauth.Error{Status: http.StatusUnsupportedMediaType, Code: "unsupported-media-type",
			Message: "Content-Type must be application/json"}
	}
	return nil
}

// readBody reads a request body of at most limit bytes (413 beyond).
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		return nil, &endpointauth.Error{Status: http.StatusRequestEntityTooLarge, Code: "too-large", Message: err.Error()}
	}
	return body, nil
}

func (c *Console) ingest(w http.ResponseWriter, r *http.Request) {
	if err := checkJSON(r); err != nil {
		c.fail(w, err)
		return
	}
	body, err := readBody(w, r, maxBodyBytes)
	if err != nil {
		c.fail(w, err)
		return
	}
	q, _, err := c.authenticate(r, body, false)
	if err != nil {
		c.fail(w, err)
		return
	}
	b, err := checkBatch(body)
	if err != nil {
		c.fail(w, &endpointauth.Error{Status: http.StatusBadRequest, Code: "bad-request", Message: err.Error()})
		return
	}
	if b.Endpoint.ID != q.EndpointID {
		c.fail(w, &endpointauth.Error{Status: http.StatusForbidden, Code: endpointauth.CodeForbidden,
			Message: "the batch is from another endpoint than the one that signed it"})
		return
	}
	c.mu.Lock()
	c.batches = append(c.batches, b)
	c.mu.Unlock()
	c.answer(w, q, http.StatusAccepted, fmt.Appendf(nil, "{\"accepted\":%d}\n", len(b.Events)))
}

func (c *Console) enroll(w http.ResponseWriter, r *http.Request) {
	if err := checkJSON(r); err != nil {
		c.fail(w, err)
		return
	}
	body, err := readBody(w, r, maxEnrollBody)
	if err != nil {
		c.fail(w, err)
		return
	}
	q, _, err := c.authenticate(r, body, true)
	if err != nil {
		c.fail(w, err)
		return
	}
	var er endpointauth.EnrollRequest
	_ = json.Unmarshal(body, &er) // authenticate decoded it strictly
	now := c.clock()
	c.mu.Lock()
	tok := c.tokens[hex.EncodeToString(endpointauth.HashToken(er.Token))]
	var refusal *endpointauth.Error
	status := http.StatusOK
	drop := false
	ep := c.endpoints[er.Endpoint.ID]
	key, _ := endpointauth.DecodePublicKey(er.PublicKey)
	switch {
	case tok == nil || tok.revoked || !now.Before(tok.expires):
		refusal = &endpointauth.Error{Status: http.StatusForbidden, Code: endpointauth.CodeToken,
			Message: "the enrollment token is unknown, expired or revoked"}
	case ep != nil && (ep.Revoked || !ep.Key.Equal(key)):
		refusal = &endpointauth.Error{Status: http.StatusConflict, Code: endpointauth.CodeConflict,
			Message: "this endpoint ID is enrolled with another key, or was revoked"}
	case ep == nil && tok.uses <= 0:
		refusal = &endpointauth.Error{Status: http.StatusForbidden, Code: endpointauth.CodeToken,
			Message: "the enrollment token is used up"}
	case ep == nil:
		tok.uses--
		ep = &Endpoint{ID: er.Endpoint.ID, Hostname: er.Endpoint.Hostname, Policy: tok.policy, Key: key}
		c.endpoints[ep.ID] = ep
		status = http.StatusCreated
		drop, c.dropAnswer = c.dropAnswer, false
	}
	if ep != nil {
		snapshot := *ep
		ep = &snapshot
	}
	c.mu.Unlock()
	if refusal != nil {
		c.fail(w, refusal)
		return
	}
	if drop {
		dropConnection(w)
		return
	}
	cert, err := c.issue(ep)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	consoleKey, _ := endpointauth.EncodePublicKey(c.ConsoleKey())
	data, _ := json.Marshal(endpointauth.EnrollResponse{EndpointID: ep.ID, Policy: ep.Policy, Certificate: cert, ConsoleKey: consoleKey})
	c.answer(w, q, status, append(data, '\n'))
}

// dropConnection closes the connection without an answer, as a network
// failure after the console acted would.
func dropConnection(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "the connection cannot be dropped", http.StatusInternalServerError)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = conn.Close()
}

func (c *Console) renew(w http.ResponseWriter, r *http.Request) {
	if err := checkJSON(r); err != nil {
		c.fail(w, err)
		return
	}
	body, err := readBody(w, r, maxEnrollBody)
	if err != nil {
		c.fail(w, err)
		return
	}
	q, ep, err := c.authenticate(r, body, false)
	if err != nil {
		c.fail(w, err)
		return
	}
	if strings.TrimSpace(string(body)) != "{}" {
		c.fail(w, &endpointauth.Error{Status: http.StatusBadRequest, Code: "bad-request", Message: "the body must be {}"})
		return
	}
	cert, err := c.issue(ep)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data, _ := json.Marshal(endpointauth.CertificateResponse{Certificate: cert})
	c.answer(w, q, http.StatusOK, append(data, '\n'))
}

// issue returns a PEM client certificate for ep from the endpoint CA.
func (c *Console) issue(ep *Endpoint) (string, error) {
	u, _ := url.Parse(endpointauth.EndpointURI(ep.ID))
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := c.clock()
	c.mu.Lock()
	validity := c.certValidity
	c.mu.Unlock()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: ep.ID},
		URIs:         []*url.URL{u},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.ca, ep.Key, c.caKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

// authenticate checks a request in the order docs/protocol lists. body is
// the request body (nil for a GET). For an enrollment the key is the one in
// the body, and there is no client certificate or revocation to check.
func (c *Console) authenticate(r *http.Request, body []byte, enroll bool) (*endpointauth.Request, *Endpoint, error) {
	unauthenticated := func(msg string) error {
		return &endpointauth.Error{Status: http.StatusUnauthorized, Code: endpointauth.CodeUnauthenticated, Message: msg}
	}
	now := c.clock()
	q, err := endpointauth.ParseRequest(r, now)
	if err != nil {
		return nil, nil, err
	}
	if err := q.CheckBody(body); err != nil {
		return nil, nil, err
	}
	c.mu.Lock()
	var ep *Endpoint
	if stored := c.endpoints[q.EndpointID]; stored != nil {
		snapshot := *stored
		ep = &snapshot
	}
	c.mu.Unlock()
	var key *ecdsa.PublicKey
	switch {
	case enroll:
		var er endpointauth.EnrollRequest
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&er); err != nil {
			return nil, nil, &endpointauth.Error{Status: http.StatusBadRequest, Code: "bad-request", Message: "invalid enrollment: " + err.Error()}
		}
		if err := checkEndpoint(er.Endpoint); err != nil {
			return nil, nil, &endpointauth.Error{Status: http.StatusBadRequest, Code: "bad-request", Message: err.Error()}
		}
		if key, err = endpointauth.DecodePublicKey(er.PublicKey); err != nil {
			return nil, nil, &endpointauth.Error{Status: http.StatusBadRequest, Code: "bad-request", Message: "publicKey: " + err.Error()}
		}
		if er.Endpoint.ID != q.EndpointID {
			return nil, nil, unauthenticated("the enrollment is not for the endpoint that signed it")
		}
	case ep != nil:
		key = ep.Key
	default:
		return nil, nil, unauthenticated("the request's signature doesn't verify with this endpoint's key")
	}
	if err := q.Verify(key); err != nil {
		return nil, nil, err
	}
	if !enroll {
		// The TLS stack verified the chain against the endpoint CA, and its
		// validity. What is left to check is that it is this endpoint's.
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			return nil, nil, &endpointauth.Error{Status: http.StatusUnauthorized, Code: endpointauth.CodeCertificate,
				Message: "no client certificate: enroll this endpoint again"}
		}
		if err := endpointauth.MatchCertificate(r.TLS.PeerCertificates[0], ep.ID, ep.Key); err != nil {
			return nil, nil, &endpointauth.Error{Status: http.StatusUnauthorized, Code: endpointauth.CodeCertificate, Message: err.Error()}
		}
		if ep.Revoked {
			return nil, nil, &endpointauth.Error{Status: http.StatusForbidden, Code: endpointauth.CodeRevoked,
				Message: "this endpoint was revoked: reset it and enroll it as a new endpoint"}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, exp := range c.nonces {
		if now.After(exp) {
			delete(c.nonces, k)
		}
	}
	if _, seen := c.nonces[q.EndpointID+" "+q.Nonce]; seen {
		return nil, nil, &endpointauth.Error{Status: http.StatusUnauthorized, Code: endpointauth.CodeReplayed,
			Message: "this request's nonce was used before"}
	}
	c.nonces[q.EndpointID+" "+q.Nonce] = q.NonceExpires()
	return q, ep, nil
}

// answer writes an answer, signed when it answers a signed request.
func (c *Console) answer(w http.ResponseWriter, q *endpointauth.Request, status int, body []byte) {
	if body != nil {
		w.Header().Set("Content-Type", "application/json")
	}
	if q != nil {
		c.mu.Lock()
		key := c.key
		c.mu.Unlock()
		if err := (&endpointauth.ResponseSigner{Key: key, Now: c.clock}).Sign(w.Header(), status, body, q); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(status)
	// #nosec G705 -- a test server's JSON body, not HTML.
	_, _ = w.Write(body) // the client sees a short body
}

// fail writes an error answer in the protocol's form.
func (c *Console) fail(w http.ResponseWriter, err error) {
	var e *endpointauth.Error
	if !errors.As(err, &e) {
		e = &endpointauth.Error{Status: http.StatusInternalServerError, Code: "internal", Message: err.Error()}
	}
	c.mu.Lock()
	c.refusals = append(c.refusals, e.Code)
	c.mu.Unlock()
	data, _ := json.Marshal(endpointauth.ErrorResponse{Error: e.Code, Message: e.Message})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)
	_, _ = w.Write(append(data, '\n'))
}

// checkBatch validates a POST /api/v1/events body as docs/protocol requires.
// The whole batch is rejected if any part of it is invalid.
func checkBatch(body []byte) (audit.Batch, error) {
	var b audit.Batch
	if err := audit.CheckKeys(body, b); err != nil {
		return b, fmt.Errorf("invalid batch: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return b, fmt.Errorf("invalid batch: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return b, errors.New("invalid batch: data after the JSON object")
	}
	if err := checkEndpoint(b.Endpoint); err != nil {
		return b, err
	}
	switch {
	case b.Events == nil:
		return b, errors.New("events must be a list")
	case len(b.Events) > maxBatchEvents:
		return b, fmt.Errorf("more than %d events", maxBatchEvents)
	}
	for i, raw := range b.Events {
		if _, err := audit.ParseLine(raw); err != nil {
			return b, fmt.Errorf("event %d: %v", i, err)
		}
	}
	return b, nil
}

// checkEndpoint applies docs/protocol's rules for an endpoint description.
func checkEndpoint(e audit.Endpoint) error {
	switch {
	case !uuidRE.MatchString(e.ID):
		return errors.New("endpoint.id must be a lowercase UUID")
	case e.Version == "":
		return errors.New("endpoint.version is required")
	case !isLabel(e.Hostname) || !isLabel(e.Version):
		return errors.New("endpoint.hostname and endpoint.version must be short printable text")
	}
	return nil
}

// etagMatches implements If-None-Match with the weak comparison of RFC 9110.
func etagMatches(header, etag string) bool {
	for _, t := range strings.Split(header, ",") {
		t = strings.TrimPrefix(strings.TrimSpace(t), "W/")
		if t == "*" || t == etag {
			return true
		}
	}
	return false
}

func isLabel(s string) bool {
	if len(s) > maxLabel || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
