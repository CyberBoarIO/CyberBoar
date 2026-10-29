package protocoltest

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/pkg/audit"
	"cyberboar.dev/cyberboar/pkg/endpointauth"
)

// The golden event batches in testdata/protocol/events are accepted or rejected as their names say.
func TestGoldenBatches(t *testing.T) {
	files, _ := filepath.Glob("../../testdata/protocol/events/*.json")
	if len(files) == 0 {
		t.Fatal("no golden batches")
	}
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		_, err = checkBatch(body)
		switch name := filepath.Base(f); {
		case strings.HasPrefix(name, "accept-") && err != nil:
			t.Errorf("%s rejected: %v", name, err)
		case strings.HasPrefix(name, "reject-") && err == nil:
			t.Errorf("%s accepted", name)
		case !strings.HasPrefix(name, "accept-") && !strings.HasPrefix(name, "reject-"):
			t.Errorf("%s: name must start with accept- or reject-", name)
		}
	}
}

// The golden requests in testdata/protocol/auth get the verdicts their
// names give from this console's checks (docs/protocol, "Golden files"),
// with the client certificate from the golden renewal answer.
func TestGoldenRequests(t *testing.T) {
	const dir = "../../testdata/protocol/auth/"
	c := newConsole(t, "", nil)
	c.SetClock(func() time.Time { return time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC) })
	b, _ := pem.Decode(read(t, dir+"insecure-endpoint.pub"))
	k, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ep := &Endpoint{ID: "3f1c6a52-8d4e-4b7a-9c21-5e0f7d9a1b24", Policy: "baseline", Key: k.(*ecdsa.PublicKey)}
	c.endpoints[ep.ID] = ep

	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(read(t, dir+"responses/accept-certificate.http"))), nil)
	if err != nil {
		t.Fatal(err)
	}
	var cr endpointauth.CertificateResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		t.Fatal(err)
	}
	cb, _ := pem.Decode([]byte(cr.Certificate))
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	files, _ := filepath.Glob(dir + "requests/*.http")
	sort.SliceStable(files, func(i, j int) bool {
		return strings.Contains(files[i], "/accept-") && strings.Contains(files[j], "/reject-")
	})
	if len(files) < 10 {
		t.Fatalf("only %d golden requests", len(files))
	}
	for _, f := range files {
		name := filepath.Base(f)
		r, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(read(t, f))))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(r.Body)
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		_, _, err = c.authenticate(r, body, r.URL.Path == endpointauth.EnrollPath)
		if strings.HasPrefix(name, "accept-") {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		want, _, _ := strings.Cut(strings.TrimPrefix(name, "reject-"), "-")
		var e *endpointauth.Error
		if !errors.As(err, &e) || e.Code != want {
			t.Errorf("%s: got %v, want code %q", name, err, want)
		}
	}
}

// Policy assignment and revocation can run while requests are being checked or answered.
func TestConcurrentEndpointUpdates(t *testing.T) {
	for _, mode := range []string{"authenticate-assign", "authenticate-revoke", "enroll-assign"} {
		t.Run(mode, func(t *testing.T) {
			c := newConsole(t, "", nil)
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			const id = "3f1c6a52-8d4e-4b7a-9c21-5e0f7d9a1b24"
			c.endpoints[id] = &Endpoint{ID: id, Policy: "baseline", Key: &key.PublicKey}
			certPEM, err := c.issue(c.endpoints[id])
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode([]byte(certPEM))
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			pub, err := endpointauth.EncodePublicKey(&key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(endpointauth.EnrollRequest{Token: c.Token("baseline", 1),
				Endpoint: audit.Endpoint{ID: id, Version: "v1.0.0-rc.1"}, PublicKey: pub})
			if err != nil {
				t.Fatal(err)
			}
			signer := &endpointauth.Signer{ID: id, Key: key, Now: c.clock}
			stop := make(chan struct{})
			var updates sync.WaitGroup
			updates.Go(func() {
				for {
					select {
					case <-stop:
						return
					default:
						c.Assign(id, "updated")
						if mode == "authenticate-revoke" {
							c.Revoke(id)
						}
					}
				}
			})
			defer func() {
				close(stop)
				updates.Wait()
			}()
			for range 100 {
				if mode == "enroll-assign" {
					r := httptest.NewRequest(http.MethodPost, "https://console.test"+endpointauth.EnrollPath, bytes.NewReader(body))
					r.Header.Set("Content-Type", "application/json")
					if err := signer.Sign(r, body); err != nil {
						t.Fatal(err)
					}
					w := httptest.NewRecorder()
					c.enroll(w, r)
					if w.Code != http.StatusOK {
						t.Fatalf("enrollment: %d %s", w.Code, w.Body)
					}
					continue
				}
				r := httptest.NewRequest(http.MethodGet, "https://console.test/api/v1/bundles/updated", nil)
				if err := signer.Sign(r, nil); err != nil {
					t.Fatal(err)
				}
				r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
				_, ep, err := c.authenticate(r, nil, false)
				if mode == "authenticate-revoke" && err != nil {
					var refusal *endpointauth.Error
					if errors.As(err, &refusal) && refusal.Code == endpointauth.CodeRevoked {
						continue
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				if ep.Policy != "baseline" && ep.Policy != "updated" {
					t.Fatalf("unexpected policy: %q", ep.Policy)
				}
			}
		})
	}
}

func read(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
