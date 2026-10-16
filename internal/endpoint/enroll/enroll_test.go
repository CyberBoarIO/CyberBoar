package enroll

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/internal/endpoint/httpsclient"
	"cyberboar.dev/cyberboar/internal/endpoint/keystore"
	"cyberboar.dev/cyberboar/internal/protocoltest"
	"cyberboar.dev/cyberboar/pkg/audit"
	"cyberboar.dev/cyberboar/pkg/endpointauth"
)

func options(t *testing.T, c *protocoltest.Console, token string) Options {
	return Options{Server: c.URL, Token: token, StateDir: filepath.Join(t.TempDir(), "state"), Hostname: "dev-laptop",
		Version: "v1", TLS: httpsclient.TLS{CAFile: c.CAFile(t)}, KeyStorage: keystore.File}
}

func enrolled(t *testing.T, c *protocoltest.Console) (*Endpoint, Options) {
	t.Helper()
	o := options(t, c, c.Token("baseline", 1))
	ep, how, err := Once(context.Background(), o)
	if err != nil || how != Enrolled {
		t.Fatalf("enroll: %v %v", how, err)
	}
	return ep, o
}

// heartbeat sends an empty batch with the endpoint's client.
func heartbeat(t *testing.T, ep *Endpoint, client *http.Client) (*http.Response, error) {
	t.Helper()
	body, _ := json.Marshal(audit.Batch{Endpoint: audit.Endpoint{ID: ep.EndpointID, Version: "v1"}, Events: []json.RawMessage{}})
	req, _ := http.NewRequest("POST", ep.Console+"/api/v1/events", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	return resp, err
}

func TestEnrollAndSend(t *testing.T) {
	c := protocoltest.New(t, "", nil)
	ep, o := enrolled(t, c)
	if ep.Policy != "baseline" || ep.Console != c.URL || !endpointauth.ValidEndpointID(ep.EndpointID) {
		t.Fatalf("enrollment %+v", ep.Enrollment)
	}
	eps := c.Endpoints()
	if len(eps) != 1 || eps[0].ID != ep.EndpointID || eps[0].Hostname != "dev-laptop" {
		t.Fatalf("console has %+v", eps)
	}
	for _, f := range []string{KeyFile, CertificateFile, EnrollmentFile, IDFile} {
		if _, err := os.Stat(filepath.Join(o.StateDir, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	loaded, err := Load(o.StateDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := loaded.Client(o.TLS)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := heartbeat(t, loaded, client); err != nil || resp.StatusCode != 202 {
		t.Fatalf("heartbeat: %v %v (refusals %v)", resp, err, c.Refusals())
	}
	if len(c.Batches()) != 1 {
		t.Fatalf("console got %d batches", len(c.Batches()))
	}

	// Enrolled and current: no token needed, nothing sent.
	before := len(c.Endpoints())
	o.Token = ""
	if _, how, err := Once(context.Background(), o); err != nil || how != Already {
		t.Fatalf("again: %v %v", how, err)
	}
	if len(c.Endpoints()) != before {
		t.Error("enrolled twice")
	}
	other := protocoltest.New(t, "", nil)
	o.Server, o.TLS = other.URL, httpsclient.TLS{CAFile: other.CAFile(t)}
	o.Token = other.Token("baseline", 1)
	if _, _, err := Once(context.Background(), o); err == nil || !strings.Contains(err.Error(), "enrolled with") {
		t.Fatalf("moving to another console: %v", err)
	}
}

// Without a client certificate, or with someone else's, the console refuses
// even a validly signed request.
func TestClientCertificateRequired(t *testing.T) {
	c := protocoltest.New(t, "", nil)
	ep, o := enrolled(t, c)
	client, _ := ep.Client(o.TLS)
	client.Transport.(*transport).base.(*http.Transport).TLSClientConfig.GetClientCertificate = nil
	if resp, err := heartbeat(t, ep, client); err != nil || resp.StatusCode != 401 {
		t.Fatalf("no certificate: %v %v", resp, err)
	}
	other, _ := enrolled(t, c)
	client, _ = ep.Client(o.TLS)
	client.Transport.(*transport).base.(*http.Transport).TLSClientConfig.GetClientCertificate =
		func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return other.Certificate(), nil }
	if resp, err := heartbeat(t, ep, client); err != nil || resp.StatusCode != 401 {
		t.Fatalf("another endpoint's certificate: %v %v", resp, err)
	}
	if got := c.Refusals(); !slices.Equal(got, []string{"certificate", "certificate"}) {
		t.Errorf("refusals %v", got)
	}
}

// An answer the pinned key didn't sign is an error, never a response: a
// console whose key changed can't make ship believe a batch arrived.
func TestForgedAnswerIsAnError(t *testing.T) {
	c := protocoltest.New(t, "", nil)
	ep, o := enrolled(t, c)
	client, _ := ep.Client(o.TLS)
	c.ReplaceKey(t)
	resp, err := heartbeat(t, ep, client)
	if err == nil || !strings.Contains(err.Error(), "not the console's") {
		t.Fatalf("forged 202: %v %v", resp, err)
	}
	if len(c.Batches()) != 1 {
		t.Fatal("the console didn't get the batch")
	}
}

func TestTransportTalksOnlyToItsConsole(t *testing.T) {
	c := protocoltest.New(t, "", nil)
	ep, o := enrolled(t, c)
	client, _ := ep.Client(o.TLS)
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("a request reached another server: %s", r.Header.Get("Signature-Input"))
	}))
	defer other.Close()
	for _, u := range []string{other.URL + "/api/v1/events", strings.Replace(c.URL, "https:", "http:", 1) + "/api/v1/events"} {
		if _, err := client.Get(u); err == nil || !strings.Contains(err.Error(), "talks to nothing else") {
			t.Errorf("%s: %v", u, err)
		}
	}
}

// An endpoint keeps the policy it enrolled with until it enrolls again,
// which after removing its certificate gets the console's current one
// (docs/deploy-mdm.md).
func TestReassignedPolicy(t *testing.T) {
	c := protocoltest.New(t, "", nil)
	ep, o := enrolled(t, c)
	c.Assign(ep.EndpointID, "strict")
	if again, how, err := Once(context.Background(), o); err != nil || how != Already || again.Policy != "baseline" {
		t.Fatalf("enrolled endpoint: %v %v", how, err)
	}
	if err := os.Remove(filepath.Join(o.StateDir, CertificateFile)); err != nil {
		t.Fatal(err)
	}
	o.Token = c.Token("baseline", 0)
	if again, how, err := Once(context.Background(), o); err != nil || how != Reenrolled || again.Policy != "strict" {
		t.Fatalf("enrolling again: %v %v", how, err)
	}
	if ep, err := Load(o.StateDir, nil); err != nil || ep.Policy != "strict" {
		t.Fatalf("reload: %v", err)
	}
}

func TestRevokedEndpointIsRefused(t *testing.T) {
	c := protocoltest.New(t, "", nil)
	ep, o := enrolled(t, c)
	c.Revoke(ep.EndpointID)
	client, _ := ep.Client(o.TLS)
	if resp, err := heartbeat(t, ep, client); err != nil || resp.StatusCode != 403 {
		t.Fatalf("revoked: %v %v", resp, err)
	}
	// Once its certificate expired, it can't enroll again either, not even
	// with a new token.
	later := func() time.Time { return time.Now().Add(60 * 24 * time.Hour) }
	c.SetClock(later)
	o.Now = later
	o.Token = c.Token("baseline", 1)
	if _, _, err := Once(context.Background(), o); err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("re-enrolling a revoked endpoint: %v", err)
	}
}

// When the console's answer is lost, enrolling again completes the
// enrollment with the same key and without spending the token again.
func TestLostAnswerIsRetried(t *testing.T) {
	c := protocoltest.New(t, "", nil)
	c.DropNextEnrollmentAnswer()
	o := options(t, c, c.Token("baseline", 1))
	if _, _, err := Once(context.Background(), o); err == nil || !strings.Contains(err.Error(), "enrolling with") {
		t.Fatalf("lost answer: %v", err)
	}
	if _, err := Load(o.StateDir, nil); !errors.Is(err, ErrUnfinished) && err != ErrNotEnrolled {
		t.Fatalf("an unanswered enrollment loads as %v", err)
	}
	ep, how, err := Once(context.Background(), o)
	if err != nil || how != Reenrolled || ep.Policy != "baseline" {
		t.Fatalf("retry: %v %v", how, err)
	}
	if _, err := Load(o.StateDir, nil); err != nil {
		t.Errorf("after the retry: %v", err)
	}
	if n := len(c.Endpoints()); n != 1 {
		t.Errorf("%d endpoints", n)
	}
	// The token had one use: a second machine can't use it.
	o2 := options(t, c, o.Token)
	if _, _, err := Once(context.Background(), o2); err == nil || !strings.Contains(err.Error(), "token") {
		t.Errorf("a used-up token enrolled another endpoint: %v", err)
	}
}

func TestExpiredCertificate(t *testing.T) {
	c := protocoltest.New(t, "", nil)
	_, o := enrolled(t, c)
	later := func() time.Time { return time.Now().Add(31 * 24 * time.Hour) }
	c.SetClock(later)
	o.Now = later
	ep, err := Load(o.StateDir, later)
	if err != nil {
		t.Fatalf("an expired certificate must still load: %v", err)
	}
	client, _ := ep.Client(o.TLS)
	if _, err := heartbeat(t, ep, client); !errors.Is(err, ErrExpired) {
		t.Fatalf("sending with an expired certificate: %v", err)
	}
	if _, err := ep.RenewIfDue(context.Background(), client); !errors.Is(err, ErrExpired) {
		t.Fatalf("renewing an expired certificate: %v", err)
	}
	o.Token = ""
	if _, _, err := Once(context.Background(), o); err != ErrNoToken {
		t.Fatalf("expired without a token: %v", err)
	}
	o.Token = c.Token("baseline", 0) // no uses: the endpoint is known
	ep, how, err := Once(context.Background(), o)
	if err != nil || how != Reenrolled {
		t.Fatalf("re-enroll: %v %v", how, err)
	}
	client, _ = ep.Client(o.TLS)
	if resp, err := heartbeat(t, ep, client); err != nil || resp.StatusCode != 202 {
		t.Fatalf("after re-enrolling: %v %v", resp, err)
	}
}

func TestRenewIfDue(t *testing.T) {
	c := protocoltest.New(t, "", nil)
	c.SetCertValidity(2 * time.Hour)
	ep, o := enrolled(t, c)
	first := ep.Certificate().Leaf
	client, _ := ep.Client(o.TLS)
	if renewed, err := ep.RenewIfDue(context.Background(), client); err != nil || renewed {
		t.Fatalf("a new certificate was renewed: %v %v", renewed, err)
	}
	later := func() time.Time { return time.Now().Add(61 * time.Minute) }
	c.SetClock(later)
	ep, err := Load(o.StateDir, later)
	if err != nil {
		t.Fatal(err)
	}
	client, _ = ep.Client(o.TLS)
	if renewed, err := ep.RenewIfDue(context.Background(), client); err != nil || !renewed {
		t.Fatalf("renew: %v %v (refusals %v)", renewed, err, c.Refusals())
	}
	second := ep.Certificate().Leaf
	if !second.NotAfter.After(first.NotAfter) {
		t.Fatal("the certificate didn't change")
	}
	if resp, err := heartbeat(t, ep, client); err != nil || resp.StatusCode != 202 {
		t.Fatalf("with the new certificate: %v %v", resp, err)
	}
	// Another run sees the renewed certificate on disk and doesn't renew.
	again, err := Load(o.StateDir, later)
	if err != nil || !again.Certificate().Leaf.NotAfter.Equal(second.NotAfter) {
		t.Fatalf("reload: %v", err)
	}
	stale, _ := Load(o.StateDir, later)
	stale.cert.Store(&tls.Certificate{Leaf: first, Certificate: [][]byte{first.Raw}})
	if renewed, err := stale.RenewIfDue(context.Background(), client); err != nil || renewed {
		t.Errorf("renewed although the file had a current certificate: %v %v", renewed, err)
	}
}

func TestPinnedConsoleKey(t *testing.T) {
	c := protocoltest.New(t, "", nil)
	o := options(t, c, c.Token("baseline", 2))
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	o.ConsoleKey = &other.PublicKey
	if _, _, err := Once(context.Background(), o); err == nil || !strings.Contains(err.Error(), "-console-key") {
		t.Fatalf("another console key: %v", err)
	}
	if _, err := os.Stat(filepath.Join(o.StateDir, EnrollmentFile)); !errors.Is(err, os.ErrNotExist) {
		t.Error("recorded an enrollment")
	}
	// Without verifying the server, the pin is what authenticates it.
	o = options(t, c, c.Token("baseline", 1))
	o.TLS = httpsclient.TLS{SkipVerify: true}
	if _, _, err := Once(context.Background(), o); err == nil {
		t.Fatal("enrolled with neither a verified server nor a pinned key")
	}
	o.ConsoleKey = c.ConsoleKey()
	if _, how, err := Once(context.Background(), o); err != nil || how != Enrolled {
		t.Fatalf("pinned key, unverified server: %v %v", how, err)
	}
}

// An endpoint that enrolled once keeps trusting the console key it got
// then: enrolling again, for an expired certificate or an unfinished
// enrollment, can't swap it.
func TestConsoleKeyStaysPinned(t *testing.T) {
	for _, tc := range []struct {
		name    string
		breakIt func(t *testing.T, c *protocoltest.Console, o *Options)
	}{
		{"expired", func(t *testing.T, c *protocoltest.Console, o *Options) {
			later := func() time.Time { return time.Now().Add(31 * 24 * time.Hour) }
			c.SetClock(later)
			o.Now = later
		}},
		{"unfinished", func(t *testing.T, c *protocoltest.Console, o *Options) {
			if err := os.Remove(filepath.Join(o.StateDir, CertificateFile)); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := protocoltest.New(t, "", nil)
			_, o := enrolled(t, c)
			tc.breakIt(t, c, &o)
			c.ReplaceKey(t)
			o.Token = c.Token("baseline", 0)
			if _, _, err := Once(context.Background(), o); err == nil || !strings.Contains(err.Error(), "changed") {
				t.Fatalf("enrolled again with a new console key: %v", err)
			}
			if _, err := os.Stat(filepath.Join(o.StateDir, CertificateFile)); tc.name == "unfinished" && !errors.Is(err, os.ErrNotExist) {
				t.Error("installed a certificate from the new key's answer")
			}
		})
	}
}

func TestOnceRefusesBeforeSending(t *testing.T) {
	token, _ := endpointauth.NewToken()
	for name, o := range map[string]Options{
		"plain http":       {Server: "http://console.example", Token: token},
		"query":            {Server: "https://console.example?x=1", Token: token},
		"not a token":      {Server: "https://127.0.0.1:1", Token: "cyberboar_enroll_short"},
		"no token":         {Server: "https://127.0.0.1:1"},
		"skip-verify only": {Server: "https://127.0.0.1:1", Token: token, TLS: httpsclient.TLS{SkipVerify: true}},
	} {
		o.StateDir = filepath.Join(t.TempDir(), "state")
		if _, _, err := Once(context.Background(), o); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := os.Stat(o.StateDir); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: created the state directory", name)
		}
	}
}

// fakeConsole answers enrollments with whatever answer returns, signed by
// signer when it is set.
func fakeConsole(t *testing.T, answer func(id string, pub *ecdsa.PublicKey) (int, []byte), signer *ecdsa.PrivateKey) *httptest.Server {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q, err := endpointauth.ParseRequest(r, time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		var er endpointauth.EnrollRequest
		json.Unmarshal(body, &er)
		pub, _ := endpointauth.DecodePublicKey(er.PublicKey)
		status, data := answer(q.EndpointID, pub)
		if signer != nil {
			(&endpointauth.ResponseSigner{Key: signer}).Sign(w.Header(), status, data, q)
		}
		w.WriteHeader(status)
		w.Write(data)
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func certFor(t *testing.T, id string, pub *ecdsa.PublicKey, edit func(*x509.Certificate)) string {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(endpointauth.EndpointURI(id))
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: id}, URIs: []*url.URL{u},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if edit != nil {
		edit(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// An answer that isn't a signed enrollment for this endpoint and key records
// nothing.
func TestBadAnswers(t *testing.T) {
	consoleKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ck, _ := endpointauth.EncodePublicKey(&consoleKey.PublicKey)
	good := func(id string, pub *ecdsa.PublicKey) endpointauth.EnrollResponse {
		return endpointauth.EnrollResponse{EndpointID: id, Policy: "baseline", Certificate: certFor(t, id, pub, nil), ConsoleKey: ck}
	}
	js := func(v any) []byte { data, _ := json.Marshal(v); return data }
	for name, tc := range map[string]struct {
		answer func(id string, pub *ecdsa.PublicKey) (int, []byte)
		signer *ecdsa.PrivateKey
	}{
		"unsigned":              {func(id string, pub *ecdsa.PublicKey) (int, []byte) { return 201, js(good(id, pub)) }, nil},
		"signed by another key": {func(id string, pub *ecdsa.PublicKey) (int, []byte) { return 201, js(good(id, pub)) }, other},
		"not JSON":              {func(string, *ecdsa.PublicKey) (int, []byte) { return 201, []byte("ok") }, consoleKey},
		"unknown field": {func(id string, pub *ecdsa.PublicKey) (int, []byte) {
			return 201, bytes.Replace(js(good(id, pub)), []byte(`{`), []byte(`{"admin":true,`), 1)
		}, consoleKey},
		"other ID": {func(id string, pub *ecdsa.PublicKey) (int, []byte) {
			a := good(id, pub)
			a.EndpointID = "4f0c9a52-7d1e-4b8a-9c2f-1e2d3c4b5a69"
			return 201, js(a)
		}, consoleKey},
		"bad policy": {func(id string, pub *ecdsa.PublicKey) (int, []byte) {
			a := good(id, pub)
			a.Policy = "../x"
			return 201, js(a)
		}, consoleKey},
		"certificate for another key": {func(id string, pub *ecdsa.PublicKey) (int, []byte) {
			a := good(id, pub)
			a.Certificate = certFor(t, id, &other.PublicKey, nil)
			return 201, js(a)
		}, consoleKey},
		"expired certificate": {func(id string, pub *ecdsa.PublicKey) (int, []byte) {
			a := good(id, pub)
			a.Certificate = certFor(t, id, pub, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Second) })
			return 201, js(a)
		}, consoleKey},
		"server certificate": {func(id string, pub *ecdsa.PublicKey) (int, []byte) {
			a := good(id, pub)
			a.Certificate = certFor(t, id, pub, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} })
			return 201, js(a)
		}, consoleKey},
		"too large": {func(id string, pub *ecdsa.PublicKey) (int, []byte) {
			return 201, append(js(good(id, pub)), bytes.Repeat([]byte(" "), maxEnroll)...)
		}, consoleKey},
		"error status": {func(id string, pub *ecdsa.PublicKey) (int, []byte) { return 403, js(good(id, pub)) }, consoleKey},
		"202":          {func(id string, pub *ecdsa.PublicKey) (int, []byte) { return 202, js(good(id, pub)) }, consoleKey},
	} {
		t.Run(name, func(t *testing.T) {
			srv := fakeConsole(t, tc.answer, tc.signer)
			token, _ := endpointauth.NewToken()
			dir := filepath.Join(t.TempDir(), "state")
			o := Options{Server: srv.URL, Token: token, StateDir: dir, TLS: httpsclient.TLS{CAFile: protocoltest.CAFile(t, srv)}}
			if _, _, err := Once(context.Background(), o); err == nil {
				t.Fatal("accepted")
			}
			for _, f := range []string{EnrollmentFile, CertificateFile} {
				if _, err := os.Stat(filepath.Join(dir, f)); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("wrote %s (%v)", f, err)
				}
			}
		})
	}
}

// An endpoint's key stays where it was made: asking for another store
// later is an error rather than a quiet promise that isn't kept.
func TestKeyStorageIsKept(t *testing.T) {
	c := protocoltest.New(t, "", nil)
	ep, o := enrolled(t, c)
	if ep.KeyStorage() != keystore.File {
		t.Fatalf("key in %s", ep.KeyStorage())
	}
	for _, s := range []keystore.Storage{keystore.TPM, keystore.OS} {
		o.KeyStorage = s
		if _, _, err := Once(context.Background(), o); err == nil || !strings.Contains(err.Error(), "not "+string(s)) {
			t.Fatalf("enrolled with a file key, asked for %s: %v", s, err)
		}
		// An unfinished enrollment reuses its key too, and is held to the same.
		os.Remove(filepath.Join(o.StateDir, CertificateFile))
		o.Token = c.Token("baseline", 1)
		if _, _, err := Once(context.Background(), o); err == nil || !strings.Contains(err.Error(), "not "+string(s)) {
			t.Fatalf("unfinished, with a file key, asked for %s: %v", s, err)
		}
		finish := o
		finish.KeyStorage = keystore.File
		if _, how, err := Once(context.Background(), finish); err != nil || how != Reenrolled {
			t.Fatalf("finishing with the file key: %v %v", how, err)
		}
	}
	o.KeyStorage = keystore.Auto
	if _, how, err := Once(context.Background(), o); err != nil || how != Already {
		t.Fatalf("auto: %v %v", how, err)
	}
}

// A store that isn't there fails the enrollment before anything is sent or
// written; it never falls back to a file.
func TestKeyStorageUnavailable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has an OS key store; keystore's own tests cover it")
	}
	c := protocoltest.New(t, "", nil)
	o := options(t, c, c.Token("baseline", 1))
	o.KeyStorage = keystore.OS
	if _, _, err := Once(context.Background(), o); !errors.Is(err, keystore.ErrUnavailable) {
		t.Fatalf("enrolled without an OS key store: %v", err)
	}
	if _, err := os.Stat(filepath.Join(o.StateDir, KeyFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("key file: %v", err)
	}
	if len(c.Endpoints()) != 0 {
		t.Fatal("the console heard from the endpoint")
	}
}
