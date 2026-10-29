// Package enroll keeps an endpoint's enrollment with a console, as
// docs/protocol describes under "Endpoint authentication". An enrollment is
// the endpoint's P-256 key, the client certificate the console issued for it,
// and the console key it pinned.
//
// Once enrolls an endpoint. Endpoint.Client returns the HTTP client that ship
// and pull use. That client presents the certificate, signs every request and
// accepts only answers signed with the pinned key. RenewIfDue keeps the
// certificate current.
package enroll

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"cyberboar.dev/cyberboar/internal/endpoint/httpsclient"
	"cyberboar.dev/cyberboar/internal/endpoint/keystore"
	"cyberboar.dev/cyberboar/internal/endpoint/strictjson"
	"cyberboar.dev/cyberboar/pkg/audit"
	"cyberboar.dev/cyberboar/pkg/brand"
	"cyberboar.dev/cyberboar/pkg/bundle"
	"cyberboar.dev/cyberboar/pkg/endpointauth"
)

// These bound what is sent and read. The console takes requests up to 4 MiB;
// answers also need room for a bundle's JSON escaping and envelope.
const (
	maxRequest = 4 << 20
	maxAnswer  = bundle.MaxSize
	maxEnroll  = 64 << 10
)

// Endpoint is an enrolled endpoint.
type Endpoint struct {
	Enrollment
	StateDir string

	key        *keystore.Key
	consoleKey *ecdsa.PublicKey
	cert       atomic.Pointer[tls.Certificate]
	now        func() time.Time // time.Now if nil
}

func (e *Endpoint) clock() time.Time {
	if e.now != nil {
		return e.now()
	}
	return time.Now()
}

// KeyStorage says where the endpoint's key is.
func (e *Endpoint) KeyStorage() keystore.Storage { return e.key.Storage }

// KeySkipped says why the key isn't in a stronger store, when it was just
// made with keystore.Auto and a stronger store was passed over. Otherwise it
// is empty.
func (e *Endpoint) KeySkipped() string { return e.key.Skipped }

// Certificate returns the client certificate the endpoint presents.
func (e *Endpoint) Certificate() *tls.Certificate { return e.cert.Load() }

// ErrExpired is wrapped in the error for a client certificate that is no
// longer valid. The endpoint must then enroll again with a token.
var ErrExpired = errors.New("the client certificate has expired")

// checkCurrent returns an error wrapping ErrExpired once the certificate is
// no longer valid.
func (e *Endpoint) checkCurrent() error {
	leaf := e.cert.Load().Leaf
	if now := e.clock(); !now.Before(leaf.NotAfter) {
		return fmt.Errorf("%w (on %s): enroll again with `%s enroll` and a token; the endpoint keeps its key and ID",
			ErrExpired, leaf.NotAfter.UTC().Format(time.RFC3339), brand.Name)
	}
	return nil
}

// Client returns an HTTP client that talks only to the enrolled console. It
// uses TLS 1.3, verifies the server as t says, presents the endpoint's client
// certificate, signs every request, and checks every answer below 400 against
// the pinned console key. An answer that fails the check is an error, never a
// response, so a forged 202 can't make ship drop events.
func (e *Endpoint) Client(t httpsclient.TLS) (*http.Client, error) {
	c, err := httpsclient.New(t)
	if err != nil {
		return nil, err
	}
	base, ok := c.Transport.(*http.Transport)
	if !ok {
		return nil, errors.New("unexpected HTTP transport")
	}
	base.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return e.cert.Load(), nil
	}
	console, err := url.Parse(e.Console)
	if err != nil {
		return nil, err
	}
	c.Transport = &transport{base: base, e: e, console: console}
	return c, nil
}

// installCertificate checks a certificate chain from the console and makes
// it the one the endpoint presents, on disk and in memory.
func (e *Endpoint) installCertificate(chainPEM string) error {
	pub := e.key.Public().(*ecdsa.PublicKey)
	chain, err := endpointauth.CheckCertificate([]byte(chainPEM), e.EndpointID, pub, e.clock())
	if err != nil {
		return fmt.Errorf("the console's certificate: %v", err)
	}
	cert := &tls.Certificate{PrivateKey: e.key, Leaf: chain[0]}
	for _, c := range chain {
		cert.Certificate = append(cert.Certificate, c.Raw)
	}
	if err := writeReplace(filepath.Join(e.StateDir, CertificateFile), []byte(chainPEM)); err != nil {
		return err
	}
	e.cert.Store(cert)
	return nil
}

// Renew asks the console for a new client certificate for the same key
// (POST /api/v1/endpoint/certificate) and installs it. client is the one
// Client returned. A failure leaves the current certificate in place.
func (e *Endpoint) Renew(ctx context.Context, client *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.Console+endpointauth.CertificatePath, strings.NewReader("{}\n"))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("renewing the client certificate: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("renewing the client certificate: %v", answerError(resp))
	}
	data, _ := io.ReadAll(resp.Body) // already read and checked by the transport
	var cr endpointauth.CertificateResponse
	if err := strictjson.Decode(data, &cr); err != nil {
		return fmt.Errorf("renewing the client certificate: the answer is not a certificate: %v", err)
	}
	return e.installCertificate(cr.Certificate)
}

// RenewIfDue renews the client certificate once half its lifetime has
// passed (docs/protocol), and reports whether it did. It first rereads the
// certificate file, which another run may have renewed. An expired
// certificate can't be renewed, and the error then wraps ErrExpired.
func (e *Endpoint) RenewIfDue(ctx context.Context, client *http.Client) (renewed bool, err error) {
	if data, err := readPrivate(filepath.Join(e.StateDir, CertificateFile), maxCertFile); err == nil {
		if c, err := parseChain(data, e.EndpointID, e.key.Public().(*ecdsa.PublicKey)); err == nil &&
			c.Leaf.NotAfter.After(e.cert.Load().Leaf.NotAfter) {
			c.PrivateKey = e.key
			e.cert.Store(c)
		}
	}
	if err := e.checkCurrent(); err != nil {
		return false, err
	}
	leaf := e.cert.Load().Leaf
	if e.clock().Before(leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)) {
		return false, nil
	}
	if err := e.Renew(ctx, client); err != nil {
		return false, err
	}
	return true, nil
}

// checkStorage refuses an existing key that isn't in the store asked for.
// Asking for the TPM and quietly going on with a file key would leave an
// administrator believing the key can't be copied. An empty want, or Auto,
// accepts any store.
func checkStorage(k *keystore.Key, want keystore.Storage, stateDir string) error {
	if want == "" || want == keystore.Auto || k.Storage == want {
		return nil
	}
	return fmt.Errorf("the endpoint key is in %s, not %s: to make a new key, remove %s, %s, %s and %s from %s and enroll again",
		k.Storage, want, KeyFile, CertificateFile, EnrollmentFile, IDFile, stateDir)
}

// Options configure an enrollment.
type Options struct {
	Server     string // console base URL, e.g. https://console.example
	Token      string // enrollment token
	StateDir   string
	Hostname   string
	Version    string
	TLS        httpsclient.TLS
	ConsoleKey *ecdsa.PublicKey // the console key to pin before enrolling, required with TLS.SkipVerify
	KeyStorage keystore.Storage // where to make the endpoint key, keystore.Auto if empty
	Now        func() time.Time // time.Now if nil
}

// Outcome says what Once did.
type Outcome int

// What Once did.
const (
	Already    Outcome = iota // already enrolled with this console with a valid certificate, so nothing was sent
	Enrolled                  // a new enrollment (201)
	Reenrolled                // the console knew this key (200) after a lost answer or an expired certificate
)

// ErrNoToken is returned by Once when the endpoint needs to enroll and no
// token was given.
var ErrNoToken = errors.New("no enrollment token")

// Once makes sure the endpoint is enrolled with the console o.Server and
// returns it. An endpoint already enrolled there with a valid certificate
// needs no token and sends nothing, so an MDM script can run this on every
// check-in. An endpoint enrolled with another console is an error, because
// moving it means starting over. With a token, an unfinished enrollment
// completes and an expired certificate is replaced, both with the same key
// and ID.
func Once(ctx context.Context, o Options) (*Endpoint, Outcome, error) {
	server := strings.TrimSuffix(o.Server, "/")
	if err := checkBaseURL(server); err != nil {
		return nil, 0, err
	}
	if o.TLS.SkipVerify && o.ConsoleKey == nil {
		return nil, 0, errors.New("with the server's certificate unchecked, nothing would authenticate the console: give its key (--console-key), or verify the server (--ca)")
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	// prev is the console key an earlier enrollment trusted. The console
	// can't change it by answering a new enrollment.
	var prev *ecdsa.PublicKey
	cur, err := Load(o.StateDir, o.Now)
	switch {
	case err == nil:
		prev = cur.consoleKey
		if cur.Console != server {
			return nil, 0, fmt.Errorf("this endpoint is enrolled with %s; to move it, remove %s, %s, %s and %s from %s first",
				cur.Console, EnrollmentFile, CertificateFile, KeyFile, IDFile, o.StateDir)
		}
		if o.ConsoleKey != nil && !o.ConsoleKey.Equal(cur.consoleKey) {
			return nil, 0, errors.New("this endpoint is enrolled with a console key other than the one given")
		}
		if err := checkStorage(cur.key, o.KeyStorage, o.StateDir); err != nil {
			return nil, 0, err
		}
		if cur.checkCurrent() == nil {
			return cur, Already, nil
		}
	case errors.Is(err, ErrNotEnrolled) || errors.Is(err, ErrUnfinished):
		// A record left by an unfinished enrollment still says which console,
		// and which key it answers with.
		rec, rerr := LoadEnrollment(o.StateDir)
		switch {
		case rerr == nil && rec.Console != server:
			return nil, 0, fmt.Errorf("this endpoint's enrollment with %s is unfinished; finish it, or remove %s from %s first",
				rec.Console, EnrollmentFile, o.StateDir)
		case rerr == nil:
			prev, _ = rec.check()
		case !errors.Is(rerr, ErrNotEnrolled):
			return nil, 0, rerr
		}
		if prev != nil && o.ConsoleKey != nil && !o.ConsoleKey.Equal(prev) {
			return nil, 0, errors.New("this endpoint is enrolled with a console key other than the one given")
		}
	default:
		return nil, 0, err
	}
	if o.Token == "" {
		return nil, 0, ErrNoToken
	}
	if !endpointauth.ValidToken(o.Token) {
		return nil, 0, fmt.Errorf("the token is not an enrollment token (they start with %q)", endpointauth.TokenPrefix)
	}
	if err := SecureDir(o.StateDir); err != nil {
		return nil, 0, err
	}
	id, err := EndpointID(o.StateDir)
	if err != nil {
		return nil, 0, err
	}
	keyPath := filepath.Join(o.StateDir, KeyFile)
	storage := o.KeyStorage
	if storage == "" {
		storage = keystore.Auto
	}
	key, err := LoadKey(keyPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		key, err = CreateKey(keyPath, storage)
	case err == nil:
		err = checkStorage(key, storage, o.StateDir)
	}
	if err != nil {
		return nil, 0, err
	}
	pub, err := endpointauth.EncodePublicKey(key.Public().(*ecdsa.PublicKey))
	if err != nil {
		return nil, 0, err
	}
	body, err := json.Marshal(endpointauth.EnrollRequest{
		Token:     o.Token,
		Endpoint:  audit.Endpoint{ID: id, Hostname: o.Hostname, Version: o.Version},
		PublicKey: pub,
	})
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server+endpointauth.EnrollPath, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := (&endpointauth.Signer{ID: id, Key: key, Now: now}).Sign(req, body); err != nil {
		return nil, 0, err
	}
	client, err := httpsclient.New(o.TLS)
	if err != nil {
		return nil, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("enrolling with %s: %v", server, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, 0, answerError(resp)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxEnroll+1))
	if err != nil {
		return nil, 0, err
	}
	var ans endpointauth.EnrollResponse
	if len(data) > maxEnroll || strictjson.Decode(data, &ans) != nil {
		return nil, 0, fmt.Errorf("the console's answer is not an enrollment: %.200q", data)
	}
	consoleKey, err := endpointauth.DecodePublicKey(ans.ConsoleKey)
	if err != nil {
		return nil, 0, fmt.Errorf("the console's answer: consoleKey: %v", err)
	}
	if o.ConsoleKey != nil && !o.ConsoleKey.Equal(consoleKey) {
		return nil, 0, errors.New("the console's key is not the one given (--console-key): refusing to enroll")
	}
	if prev != nil && !prev.Equal(consoleKey) {
		return nil, 0, errors.New("the console's key changed since this endpoint enrolled: refusing to trust the new one")
	}
	if err := endpointauth.VerifyResponse(resp, data, req, consoleKey, now()); err != nil {
		return nil, 0, fmt.Errorf("the console's answer: %v", err)
	}
	if ans.EndpointID != id || !endpointauth.ValidPolicyName(ans.Policy) {
		return nil, 0, fmt.Errorf("the console's answer is for endpoint %q and policy %q; this is endpoint %s", ans.EndpointID, ans.Policy, id)
	}
	ep := &Endpoint{
		Console: server, EndpointID: id, Policy: ans.Policy, ConsoleKey: ans.ConsoleKey,
		StateDir: o.StateDir, key: key, consoleKey: consoleKey, now: o.Now,
	}
	// The certificate goes first. A record without it reads as unfinished,
	// and enrolling again completes it.
	if err := ep.installCertificate(ans.Certificate); err != nil {
		return nil, 0, err
	}
	if err := saveEnrollment(o.StateDir, ep.Enrollment); err != nil {
		return nil, 0, fmt.Errorf("enrolled, but recording it failed (enroll again to finish): %v", err)
	}
	if resp.StatusCode == http.StatusOK {
		return ep, Reenrolled, nil
	}
	return ep, Enrolled, nil
}
