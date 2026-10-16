package endpointauth

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Known test keys, fixed request nonces and deterministic signatures keep seeds
// identical in the coordinator and every fuzz worker
func fuzzKey(t testing.TB, scalar byte) deterministic {
	t.Helper()
	var raw [32]byte
	raw[len(raw)-1] = scalar
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw[:])
	if err != nil {
		t.Fatal(err)
	}
	return deterministic{k}
}

func fuzzRequest(t testing.TB, target string, body []byte) (*http.Request, *ecdsa.PublicKey) {
	t.Helper()
	s := &Signer{ID: testID, Key: fuzzKey(t, 1)}
	r := httptest.NewRequest("POST", target, bytes.NewReader(body))
	if err := s.sign(r, body, testNow.Unix(), "AAAAAAAAAAAAAAAAAAAAAA"); err != nil {
		t.Fatal(err)
	}
	return r, public(s)
}

// twin returns the other valid encoding of an ECDSA signature, (r, n-s):
// ECDSA signatures are malleable, so it verifies too and isn't a forgery
func twin(sig string) string {
	raw, err := base64.StdEncoding.DecodeString(strings.Trim(strings.TrimPrefix(sig, "cyberboar="), ":"))
	if err != nil || len(raw) != 64 {
		return ""
	}
	s := new(big.Int).Sub(elliptic.P256().Params().N, new(big.Int).SetBytes(raw[32:]))
	s.FillBytes(raw[32:])
	return "cyberboar=:" + base64.StdEncoding.EncodeToString(raw) + ":"
}

// FuzzVerifyRequest: no input panics ParseRequest, and nothing but the request that was signed verifies
// The fuzzer edits the method, target and the three headers of one signed request
func FuzzVerifyRequest(f *testing.F) {
	body := []byte(`{"events":[]}`)
	orig, pub := fuzzRequest(f, "/api/v1/events", body)
	input, sig, digest := orig.Header.Get("Signature-Input"), orig.Header.Get("Signature"), orig.Header.Get("Content-Digest")
	f.Add("POST", "/api/v1/events", input, sig, digest)
	f.Add("POST", "http://console.example/api/v1/events", input, sig, digest)
	f.Add("GET", "/api/v1/events", input, sig, digest)
	f.Add("POST", "/api/v1/events?", input, sig, digest)
	f.Add("POST", "/api/v1/events", input+";x=1", sig, digest)
	f.Add("POST", "/api/v1/events", input, twin(sig), digest)
	f.Fuzz(func(t *testing.T, method, target, in, sg, dg string) {
		// Parse the request line as the console's server would
		if strings.ContainsAny(method+target, " \r\n") {
			return
		}
		r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(method + " " + target + " HTTP/1.1\r\nHost: console.example\r\n\r\n")))
		if err != nil {
			return
		}
		r.Header.Set("Signature-Input", in)
		r.Header.Set("Signature", sg)
		r.Header.Set("Content-Digest", dg)
		q, err := ParseRequest(r, testNow)
		if err != nil {
			return
		}
		if q.Verify(pub) != nil || q.CheckBody(body) != nil {
			return
		}
		if method != "POST" || r.URL.EscapedPath() != "/api/v1/events" || r.URL.RawQuery != "" || in != input ||
			sg != sig && sg != twin(sig) || dg != digest {
			t.Fatalf("a changed request verified: %q %q\n%q\n%q\n%q", method, target, in, sg, dg)
		}
	})
}

// FuzzVerifyResponse: nothing except the answer the console signed verifies
func FuzzVerifyResponse(f *testing.F) {
	console := fuzzKey(f, 2)
	req, _ := fuzzRequest(f, "https://console.example/api/v1/events", []byte("{}"))
	q, err := ParseRequest(req, testNow)
	if err != nil {
		f.Fatal(err)
	}
	body := `{"accepted":0}` + "\n"
	h := http.Header{}
	if err := (&ResponseSigner{Key: console}).sign(h, 202, []byte(body), q.sig, testNow.Unix()); err != nil {
		f.Fatal(err)
	}
	input, sig, digest := h.Get("Signature-Input"), h.Get("Signature"), h.Get("Content-Digest")
	f.Add(202, body, input, sig, digest)
	f.Add(200, body, input, sig, digest)
	f.Add(202, body+" ", input, sig, digest)
	f.Add(202, body, input, twin(sig), digest)
	f.Fuzz(func(t *testing.T, status int, b, in, sg, dg string) {
		resp := &http.Response{StatusCode: status, Header: http.Header{}}
		resp.Header.Set("Signature-Input", in)
		resp.Header.Set("Signature", sg)
		resp.Header.Set("Content-Digest", dg)
		if VerifyResponse(resp, []byte(b), req, &console.PublicKey, testNow) != nil {
			return
		}
		if status != 202 || b != body || in != input || sg != sig && sg != twin(sig) || dg != digest {
			t.Fatalf("a changed answer verified: %d %q\n%q\n%q\n%q", status, b, in, sg, dg)
		}
	})
}
