package endpointauth

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/pkg/audit"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/protocol/auth")

const authDir = "../../testdata/protocol/auth"

// The clock and endpoint every golden file is made for (docs/protocol)
var (
	goldenNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	goldenID  = "3f1c6a52-8d4e-4b7a-9c21-5e0f7d9a1b24"
)

// deterministic signs with RFC 6979 nonces, so the golden files are the same on every run
// Real signers are randomized.
type deterministic struct{ *ecdsa.PrivateKey }

func (d deterministic) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return d.PrivateKey.Sign(nil, digest, opts)
}

// goldenKey reads a test key, creating it with -update when it is missing.
func goldenKey(t *testing.T, name string) deterministic {
	t.Helper()
	path := filepath.Join(authDir, name+".key")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && *update {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalPKCS8PrivateKey(k)
		data = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := os.MkdirAll(authDir, 0o755); err != nil {
			t.Fatal(err)
		}
		err = os.WriteFile(path, data, 0o644)
	}
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(data)
	if b == nil {
		t.Fatalf("%s: no PEM block", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return deterministic{k.(*ecdsa.PrivateKey)}
}

func publicPEM(t *testing.T, pub *ecdsa.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func goldenNonce(name string) string {
	sum := sha256.Sum256([]byte(name))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// rawRequest writes req as HTTP/1.1, headers in a fixed order
func rawRequest(req *http.Request, body []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n", req.Method, req.URL.RequestURI(), req.URL.Host)
	if body != nil {
		fmt.Fprintf(&b, "Content-Type: application/json\r\nContent-Length: %d\r\n", len(body))
	}
	writeAuthHeaders(&b, req.Header)
	b.WriteString("\r\n")
	b.Write(body)
	return b.Bytes()
}

func rawResponse(status int, h http.Header, body []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n", status, http.StatusText(status), len(body))
	writeAuthHeaders(&b, h)
	b.WriteString("\r\n")
	b.Write(body)
	return b.Bytes()
}

func writeAuthHeaders(b *bytes.Buffer, h http.Header) {
	for _, k := range []string{"Content-Digest", "Signature-Input", "Signature"} {
		for _, v := range h.Values(k) {
			fmt.Fprintf(b, "%s: %s\r\n", k, v)
		}
	}
}

// goldenCert issues a client certificate for the golden endpoint
func goldenCert(t *testing.T, ca *x509.Certificate, caKey crypto.Signer, pub *ecdsa.PublicKey, serial int64) string {
	u, _ := url.Parse(EndpointURI(goldenID))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: goldenID},
		URIs:         []*url.URL{u},
		NotBefore:    goldenNow.Add(-time.Hour),
		NotAfter:     goldenNow.Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, pub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func jsonLine(t *testing.T, v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

// goldenFiles builds every file in testdata/protocol/auth but the keys
func goldenFiles(t *testing.T) map[string][]byte {
	endpoint, console, other, caKey := goldenKey(t, "insecure-endpoint"), goldenKey(t, "insecure-console"),
		goldenKey(t, "insecure-other"), goldenKey(t, "insecure-ca")
	files := map[string][]byte{
		"insecure-endpoint.pub": publicPEM(t, &endpoint.PublicKey),
		"insecure-console.pub":  publicPEM(t, &console.PublicKey),
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "insecure test endpoint CA"},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	files["insecure-ca.pem"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	batch, err := os.ReadFile("../../testdata/protocol/events/accept-batch.json")
	if err != nil {
		t.Fatal(err)
	}
	var b audit.Batch
	if err := json.Unmarshal(batch, &b); err != nil || b.Endpoint.ID != goldenID {
		t.Fatalf("events/accept-batch.json must be from endpoint %s: %v", goldenID, err)
	}
	bundleBody, err := os.ReadFile("../../testdata/protocol/bundle-baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := jsonLine(t, audit.Batch{Endpoint: b.Endpoint, Events: []json.RawMessage{}})
	tokenSum := sha256.Sum256([]byte("golden enrolment token"))
	pubKey, _ := EncodePublicKey(&endpoint.PublicKey)
	otherKey, _ := EncodePublicKey(&other.PublicKey)
	enroll := func(key string) []byte {
		return jsonLine(t, EnrollRequest{Token: TokenPrefix + base64.RawURLEncoding.EncodeToString(tokenSum[:]),
			Endpoint: b.Endpoint, PublicKey: key})
	}

	at := func(d time.Duration) int64 { return goldenNow.Add(d).Unix() }
	signed := map[string]*http.Request{} // the requests the answers are for
	request := func(name, method, path string, body []byte, created int64, nonce string, key crypto.Signer) (*http.Request, []byte) {
		req, err := http.NewRequest(method, "https://console.example"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		s := &Signer{ID: goldenID, Key: key}
		if err := s.sign(req, body, created, nonce); err != nil {
			t.Fatal(err)
		}
		signed[name] = req
		return req, body
	}
	add := func(name string, req *http.Request, body []byte) {
		files["requests/"+name+".http"] = rawRequest(req, body)
	}
	for _, c := range []struct {
		name, method, path string
		body               []byte
		created            time.Duration
		nonce              string
		key                crypto.Signer
	}{
		{"accept-bundle", "GET", "/api/v1/bundles/baseline", nil, -10 * time.Second, "accept-bundle", endpoint},
		{"accept-certificate", "POST", CertificatePath, []byte("{}\n"), -5 * time.Second, "accept-certificate", endpoint},
		{"accept-enroll", "POST", EnrollPath, enroll(pubKey), -time.Minute, "accept-enroll", endpoint},
		{"accept-events", "POST", "/api/v1/events", batch, 0, "accept-events", endpoint},
		{"reject-replayed-nonce", "POST", "/api/v1/events", heartbeat, time.Second, "accept-events", endpoint},
		{"reject-stale-expired", "POST", "/api/v1/events", heartbeat, -MaxSkew - time.Second, "expired", endpoint},
		{"reject-stale-future", "POST", "/api/v1/events", heartbeat, MaxSkew + time.Second, "future", endpoint},
		{"reject-unauthenticated-wrong-key", "POST", "/api/v1/events", heartbeat, 0, "wrong-key", other},
		{"reject-unauthenticated-enroll-other-key", "POST", EnrollPath, enroll(otherKey), 0, "other-key", endpoint},
	} {
		req, body := request(c.name, c.method, c.path, c.body, at(c.created), goldenNonce(c.nonce), c.key)
		add(c.name, req, body)
	}

	req, _ := request("tampered", "POST", "/api/v1/events", batch, at(0), goldenNonce("tampered-body"), endpoint)
	add("reject-unauthenticated-tampered-body", req, bytes.Replace(batch, []byte(`"deny"`), []byte(`"allow"`), 1))
	req, _ = request("tampered", "POST", "/api/v1/events", batch, at(0), goldenNonce("tampered-digest"), endpoint)
	tampered := bytes.Replace(batch, []byte(`"deny"`), []byte(`"allow"`), 1)
	req.Header.Set("Content-Digest", ContentDigest(tampered))
	add("reject-unauthenticated-tampered-digest", req, tampered)
	req, _ = request("tampered", "GET", "/api/v1/bundles/baseline", nil, at(0), goldenNonce("tampered-path"), endpoint)
	req.URL.Path = "/api/v1/bundles/permissive"
	add("reject-unauthenticated-tampered-path", req, nil)
	req, _ = request("tampered", "POST", "/api/v1/events", heartbeat, at(0), goldenNonce("unsigned"), endpoint)
	req.Header.Del("Signature-Input")
	req.Header.Del("Signature")
	add("reject-unauthenticated-unsigned", req, heartbeat)

	// A valid RFC 9421 signature that doesn't cover the query
	req, _ = http.NewRequest("POST", "https://console.example/api/v1/events", nil)
	params := `("@method" "@path" "content-digest");created=` + strconv.FormatInt(at(0), 10) + `;keyid="` + goldenID +
		`";nonce="` + goldenNonce("components") + `";alg="` + Algorithm + `";tag="` + requestTag + `"`
	sig, err := signBase(endpoint, []byte(`"@method": POST`+"\n"+`"@path": /api/v1/events`+"\n"+
		`"content-digest": `+ContentDigest(heartbeat)+"\n"+`"@signature-params": `+params))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Digest", ContentDigest(heartbeat))
	req.Header.Set("Signature-Input", label+"="+params)
	req.Header.Set("Signature", label+"="+sig)
	add("reject-unauthenticated-other-components", req, heartbeat)

	answer := func(name string, status int, body []byte, to string, created int64, key crypto.Signer) {
		h := http.Header{}
		s := &ResponseSigner{Key: key}
		if err := s.sign(h, status, body, strings.TrimPrefix(signed[to].Header.Get("Signature"), label+"="), created); err != nil {
			t.Fatal(err)
		}
		files["responses/"+name+".http"] = rawResponse(status, h, body)
	}
	accepted := jsonLine(t, map[string]int{"accepted": len(b.Events)})
	consoleKey, _ := EncodePublicKey(&console.PublicKey)
	answer("accept-bundle", 200, bundleBody, "accept-bundle", at(0), console)
	answer("accept-certificate", 200, jsonLine(t, CertificateResponse{Certificate: goldenCert(t, ca, caKey, &endpoint.PublicKey, 3)}),
		"accept-certificate", at(0), console)
	answer("accept-enroll", 201, jsonLine(t, EnrollResponse{EndpointID: goldenID, Policy: "baseline",
		Certificate: goldenCert(t, ca, caKey, &endpoint.PublicKey, 2), ConsoleKey: consoleKey}), "accept-enroll", at(0), console)
	answer("accept-events", 202, accepted, "accept-events", at(0), console)
	answer("reject-other-request", 202, accepted, "reject-replayed-nonce", at(0), console)
	answer("reject-stale", 202, accepted, "accept-events", at(-MaxSkew-time.Second), console)
	answer("reject-wrong-key", 202, accepted, "accept-events", at(0), other)

	h := http.Header{}
	(&ResponseSigner{Key: console}).sign(h, 202, accepted, strings.TrimPrefix(signed["accept-events"].Header.Get("Signature"), label+"="), at(0))
	files["responses/reject-tampered-status.http"] = rawResponse(200, h, accepted)
	files["responses/reject-tampered-body.http"] = rawResponse(202, h, jsonLine(t, map[string]int{"accepted": len(b.Events) + 1}))
	files["responses/reject-unsigned.http"] = rawResponse(202, http.Header{}, accepted)
	return files
}

// The golden files are what this package produces. Other implementations
// test against them (docs/protocol) - change here is a change to the protocol
func TestGoldenFiles(t *testing.T) {
	files := goldenFiles(t)
	if *update {
		for _, sub := range []string{"requests", "responses"} {
			old, _ := filepath.Glob(filepath.Join(authDir, sub, "*.http"))
			for _, f := range old {
				os.Remove(f)
			}
			if err := os.MkdirAll(filepath.Join(authDir, sub), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, want := range files {
		path := filepath.Join(authDir, name)
		if *update {
			if err := os.WriteFile(path, want, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Error(err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from what this package builds; if the protocol changed on purpose, run go test -update and describe the change in docs/protocol", name)
		}
	}
	for _, sub := range []string{"requests", "responses"} {
		have, _ := filepath.Glob(filepath.Join(authDir, sub, "*.http"))
		for _, f := range have {
			if _, ok := files[sub+"/"+filepath.Base(f)]; !ok {
				t.Errorf("%s is not built by this package; remove it or run go test -update", f)
			}
		}
	}
}

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(authDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func readPublic(t *testing.T, name string) *ecdsa.PublicKey {
	t.Helper()
	b, _ := pem.Decode(readFile(t, name))
	if b == nil {
		t.Fatalf("%s: no PEM block", name)
	}
	k, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return k.(*ecdsa.PublicKey)
}

func readRequest(t *testing.T, name string) (*http.Request, []byte) {
	t.Helper()
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(readFile(t, "requests/"+name))))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	return req, body
}

// verifier is a console's request check as docs/protocol lists it, minus
// the client certificate, which the golden files can't carry
type verifier struct {
	keys   map[string]*ecdsa.PublicKey
	nonces map[string]bool
}

func (v *verifier) check(req *http.Request, body []byte, now time.Time) error {
	q, err := ParseRequest(req, now)
	if err != nil {
		return err
	}
	if err := q.CheckBody(body); err != nil {
		return err
	}
	pub := v.keys[q.EndpointID]
	if req.URL.Path == EnrollPath {
		var er EnrollRequest
		if err := json.Unmarshal(body, &er); err != nil {
			return &Error{Status: 400, Code: "bad-request", Message: "not an enrollment"}
		}
		if pub, err = DecodePublicKey(er.PublicKey); err != nil {
			return &Error{Status: 400, Code: "bad-request", Message: err.Error()}
		}
		if er.Endpoint.ID != q.EndpointID {
			return unauthenticated("the enrollment is not for the signing endpoint")
		}
	}
	if pub == nil {
		return unauthenticated("unknown endpoint")
	}
	if err := q.Verify(pub); err != nil {
		return err
	}
	if v.nonces[q.EndpointID+" "+q.Nonce] {
		return &Error{Status: 401, Code: CodeReplayed, Message: "replayed"}
	}
	v.nonces[q.EndpointID+" "+q.Nonce] = true
	return nil
}

// The golden requests get the verdicts their names give, checked in the
// order docs/protocol prescribes: accept-* in name order, then reject-*
func TestGoldenRequests(t *testing.T) {
	v := &verifier{keys: map[string]*ecdsa.PublicKey{goldenID: readPublic(t, "insecure-endpoint.pub")}, nonces: map[string]bool{}}
	names, _ := filepath.Glob(filepath.Join(authDir, "requests", "*.http"))
	slices.SortFunc(names, func(a, b string) int {
		ra, rb := strings.Contains(a, "/reject-"), strings.Contains(b, "/reject-")
		if ra != rb {
			if ra {
				return 1
			}
			return -1
		}
		return strings.Compare(a, b)
	})
	if len(names) < 10 {
		t.Fatalf("only %d golden requests", len(names))
	}
	for _, path := range names {
		name := filepath.Base(path)
		req, body := readRequest(t, name)
		err := v.check(req, body, goldenNow)
		if strings.HasPrefix(name, "accept-") {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		want, _, _ := strings.Cut(strings.TrimPrefix(name, "reject-"), "-")
		var e *Error
		if !errors.As(err, &e) || e.Code != want {
			t.Errorf("%s: got %v, want code %q", name, err, want)
		}
	}
}

// Valid response fixtures must verify with the console's public key for the matching request
// Returned certificates must match the endpoint's ID and public key
func TestGoldenResponses(t *testing.T) {
	consolePub := readPublic(t, "insecure-console.pub")
	endpointPub := readPublic(t, "insecure-endpoint.pub")
	names, _ := filepath.Glob(filepath.Join(authDir, "responses", "*.http"))
	if len(names) < 8 {
		t.Fatalf("only %d golden answers", len(names))
	}
	for _, path := range names {
		name := filepath.Base(path)
		to := name
		if _, err := os.Stat(filepath.Join(authDir, "requests", name)); err != nil {
			to = "accept-events.http"
		}
		req, _ := readRequest(t, to)
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(readFile(t, "responses/"+name))), req)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		body, _ := io.ReadAll(resp.Body)
		err = VerifyResponse(resp, body, req, consolePub, goldenNow)
		if !strings.HasPrefix(name, "accept-") {
			if err == nil {
				t.Errorf("%s: accepted", name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if VerifyResponse(resp, body, req, &other.PublicKey, goldenNow) == nil {
			t.Errorf("%s: accepted with another console key", name)
		}
		var cert string
		switch name {
		case "accept-enroll.http":
			var er EnrollResponse
			if err := json.Unmarshal(body, &er); err != nil {
				t.Fatal(err)
			}
			if k, err := DecodePublicKey(er.ConsoleKey); err != nil || !k.Equal(consolePub) {
				t.Errorf("%s: consoleKey is not insecure-console.pub: %v", name, err)
			}
			cert = er.Certificate
		case "accept-certificate.http":
			var cr CertificateResponse
			if err := json.Unmarshal(body, &cr); err != nil {
				t.Fatal(err)
			}
			cert = cr.Certificate
		}
		if cert == "" {
			continue
		}
		chain, err := CheckCertificate([]byte(cert), goldenID, endpointPub, goldenNow)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		roots := x509.NewCertPool()
		b, _ := pem.Decode(readFile(t, "insecure-ca.pem"))
		ca, _ := x509.ParseCertificate(b.Bytes)
		roots.AddCert(ca)
		if _, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, CurrentTime: goldenNow,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			t.Errorf("%s: the certificate doesn't verify with insecure-ca.pem: %v", name, err)
		}
	}
}
