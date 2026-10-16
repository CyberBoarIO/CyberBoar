package endpointauth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testID = "0b6a3f4e-2c1d-4e5f-8a9b-0c1d2e3f4a5b"

// A fixed epoch keeps the clock component of signed fuzz seeds reproducible
var testNow = time.Unix(0, 0).UTC().Add(24 * time.Hour)

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testSigner(t testing.TB) *Signer {
	return &Signer{ID: testID, Key: newKey(t), Now: func() time.Time { return testNow }}
}

func signed(t testing.TB, s *Signer, method, target string, body []byte) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, target, bytes.NewReader(body))
	if err := s.Sign(r, body); err != nil {
		t.Fatal(err)
	}
	return r
}

func public(s *Signer) *ecdsa.PublicKey { return s.Key.Public().(*ecdsa.PublicKey) }

func TestSignVerify(t *testing.T) {
	s := testSigner(t)
	for _, tc := range []struct {
		method, target string
		body           []byte
	}{
		{"POST", "https://console.example/api/v1/events", []byte(`{"events":[]}`)},
		{"GET", "https://console.example/api/v1/bundles/base%2Fline", nil},
		{"GET", "https://console.example/api/v1/bundles?x=1", nil},
		{"GET", "https://console.example", nil},
	} {
		r := signed(t, s, tc.method, tc.target, tc.body)
		q, err := ParseRequest(r, testNow)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.target, err)
		}
		if q.EndpointID != testID || !q.Created.Equal(testNow) || len(q.Nonce) != 22 {
			t.Errorf("parsed %+v", q)
		}
		if err := q.Verify(public(s)); err != nil {
			t.Errorf("%s %s: %v", tc.method, tc.target, err)
		}
		if err := q.CheckBody(tc.body); err != nil {
			t.Errorf("%s %s: %v", tc.method, tc.target, err)
		}
		if !q.NonceExpires().Equal(testNow.Add(MaxSkew)) {
			t.Errorf("nonce expires %v", q.NonceExpires())
		}
	}
}

func TestNonceIsFresh(t *testing.T) {
	s := testSigner(t)
	a := signed(t, s, "GET", "/x", nil).Header.Get("Signature-Input")
	b := signed(t, s, "GET", "/x", nil).Header.Get("Signature-Input")
	if a == b {
		t.Fatal("two requests got the same nonce")
	}
}

// TestSignatureBases pins the wire format: endpoints sign exactly this, so a change locks them out
func TestSignatureBases(t *testing.T) {
	u, _ := url.Parse("https://console.example/api/v1/events")
	empty := "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:" // RFC 9530 §B: SHA-256 of no bytes
	base, err := requestBase("POST", u, empty, requestParams(testNow.Unix(), testID, "AAAAAAAAAAAAAAAAAAAAAA"))
	if err != nil {
		t.Fatal(err)
	}
	want := `"@method": POST
"@path": /api/v1/events
"@query": ?
"content-digest": ` + empty + `
"@signature-params": ("@method" "@path" "@query" "content-digest");created=` + strconv.FormatInt(testNow.Unix(), 10) + `;keyid="` + testID +
		`";nonce="AAAAAAAAAAAAAAAAAAAAAA";alg="ecdsa-p256-sha256";tag="cyberboar.dev/endpoint/v1"`
	if string(base) != want {
		t.Errorf("request signature base:\n%s\nwant:\n%s", base, want)
	}
	if got := ContentDigest(nil); got != empty {
		t.Errorf("digest of no bytes: %s", got)
	}
	base = responseBase(202, empty, ":c2ln:", responseParams(testNow.Unix(), strings.Repeat("ab", 32)))
	want = `"@status": 202
"content-digest": ` + empty + `
"signature";req;key="cyberboar": :c2ln:
"@signature-params": ("@status" "content-digest" "signature";req;key="cyberboar");created=` + strconv.FormatInt(testNow.Unix(), 10) + `;keyid="` +
		strings.Repeat("ab", 32) + `";alg="ecdsa-p256-sha256";tag="cyberboar.dev/console/v1"`
	if string(base) != want {
		t.Errorf("response signature base:\n%s\nwant:\n%s", base, want)
	}
}

// TestRFC9421Vector checks the signature base layout and the r‖s encoding
// against the ecdsa-p256-sha256 example of RFC 9421 (B.2.4, key B.1.3): lines
// of "name": value joined by LF, @signature-params last, no final LF
func TestRFC9421Vector(t *testing.T) {
	block, _ := pem.Decode([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf
w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END PUBLIC KEY-----`))
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	base := `"@status": 200
"content-type": application/json
"content-digest": sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:
"content-length": 23
"@signature-params": ("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"`
	if !verifyBase(k.(*ecdsa.PublicKey), []byte(base), ":wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw==:") {
		t.Fatal("RFC 9421 B.2.4 doesn't verify")
	}
}

// TestRejectedRequests covers ways a request can fail before or at the
// signature check. Each must be refused, none should reach a handler
func TestRejectedRequests(t *testing.T) {
	s := testSigner(t)
	pub := public(s)
	body := []byte(`{"events":[]}`)
	fresh := func() *http.Request { return signed(t, s, "POST", "https://console.example/api/v1/events", body) }
	orig := fresh()
	input, sig, digest := orig.Header.Get("Signature-Input"), orig.Header.Get("Signature"), orig.Header.Get("Content-Digest")

	for name, tc := range map[string]struct {
		edit func(r *http.Request)
		now  time.Time
		pub  *ecdsa.PublicKey
	}{
		"other key":         {pub: &newKey(t).PublicKey},
		"P-384 key":         {pub: &mustKey(ecdsa.GenerateKey(elliptic.P384(), rand.Reader)).PublicKey},
		"other method":      {edit: func(r *http.Request) { r.Method = "PUT" }},
		"other path":        {edit: func(r *http.Request) { r.URL.Path = "/api/v1/enroll" }},
		"query added":       {edit: func(r *http.Request) { r.URL.RawQuery = "x=1" }},
		"other digest":      {edit: func(r *http.Request) { r.Header.Set("Content-Digest", ContentDigest([]byte("x"))) }},
		"no digest":         {edit: func(r *http.Request) { r.Header.Del("Content-Digest") }},
		"two digests":       {edit: func(r *http.Request) { r.Header.Add("Content-Digest", digest) }},
		"sha-512 digest":    {edit: func(r *http.Request) { r.Header.Set("Content-Digest", "sha-512=:"+digest[9:]) }},
		"two inputs":        {edit: func(r *http.Request) { r.Header.Add("Signature-Input", input) }},
		"two signatures":    {edit: func(r *http.Request) { r.Header.Add("Signature", sig) }},
		"no signature":      {edit: func(r *http.Request) { r.Header.Del("Signature") }},
		"no input":          {edit: func(r *http.Request) { r.Header.Del("Signature-Input") }},
		"two in one header": {edit: func(r *http.Request) { r.Header.Set("Signature", sig+", "+sig) }},
		"other label":       {edit: func(r *http.Request) { r.Header.Set("Signature", "sig1"+sig[len("cyberboar"):]) }},
		"input label":       {edit: func(r *http.Request) { r.Header.Set("Signature-Input", "sig1"+input[len("cyberboar"):]) }},
		"leading zero": {edit: func(r *http.Request) {
			r.Header.Set("Signature-Input", strings.Replace(input, "created=", "created=0", 1))
		}},
		"other alg": {edit: func(r *http.Request) {
			r.Header.Set("Signature-Input", strings.Replace(input, `"ecdsa-p256-sha256"`, `"ed25519"`, 1))
		}},
		"no alg": {edit: func(r *http.Request) {
			r.Header.Set("Signature-Input", strings.Replace(input, `;alg="ecdsa-p256-sha256"`, "", 1))
		}},
		"console tag": {edit: func(r *http.Request) {
			r.Header.Set("Signature-Input", strings.Replace(input, "endpoint/v1", "console/v1", 1))
		}},
		"extra param": {edit: func(r *http.Request) { r.Header.Set("Signature-Input", input+`;expires=1`) }},
		"fewer components": {edit: func(r *http.Request) {
			r.Header.Set("Signature-Input", strings.Replace(input, ` "content-digest"`, "", 1))
		}},
		"upper-case keyid": {edit: func(r *http.Request) { r.Header.Set("Signature-Input", strings.Replace(input, "b6a", "B6A", 1)) }},
		"other keyid": {edit: func(r *http.Request) {
			r.Header.Set("Signature-Input", strings.Replace(input, testID, "1b6a3f4e-2c1d-4e5f-8a9b-0c1d2e3f4a5b", 1))
		}},
		"other nonce": {edit: func(r *http.Request) { r.Header.Set("Signature-Input", replaceNonce(input, "BBBBBBBBBBBBBBBBBBBBBB")) }},
		"short nonce": {edit: func(r *http.Request) { r.Header.Set("Signature-Input", replaceNonce(input, "BBBB")) }},
		"other created": {edit: func(r *http.Request) {
			r.Header.Set("Signature-Input", strings.Replace(input, "created="+strconv.FormatInt(testNow.Unix(), 10), "created="+strconv.FormatInt(testNow.Unix()+1, 10), 1))
		}},
		"flipped signature":   {edit: func(r *http.Request) { r.Header.Set("Signature", flip(sig)) }},
		"unpadded signature":  {edit: func(r *http.Request) { r.Header.Set("Signature", strings.TrimSuffix(sig, "==:")+":") }},
		"signature as token":  {edit: func(r *http.Request) { r.Header.Set("Signature", strings.Trim(sig[len("cyberboar="):], ":")) }},
		"zero signature":      {edit: func(r *http.Request) { r.Header.Set("Signature", "cyberboar=:"+strings.Repeat("A", 86)+"==:") }},
		"too old":             {now: testNow.Add(MaxSkew + time.Second)},
		"from the future":     {now: testNow.Add(-MaxSkew - time.Second)},
		"control char in URL": {edit: func(r *http.Request) { r.URL.RawQuery = "a\nb" }},
	} {
		r := fresh()
		r.Header.Set("Signature-Input", input)
		r.Header.Set("Signature", sig)
		r.Header.Set("Content-Digest", digest)
		if tc.edit != nil {
			tc.edit(r)
		}
		now := testNow
		if !tc.now.IsZero() {
			now = tc.now
		}
		key := pub
		if tc.pub != nil {
			key = tc.pub
		}
		q, err := ParseRequest(r, now)
		if err == nil {
			err = q.Verify(key)
		}
		if err == nil {
			err = q.CheckBody(body)
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		var ae *Error
		if !errors.As(err, &ae) || ae.Status != http.StatusUnauthorized {
			t.Errorf("%s: error %v is not a 401 *Error", name, err)
		}
	}

	// The window's edges are inside it
	for _, now := range []time.Time{testNow.Add(MaxSkew), testNow.Add(-MaxSkew)} {
		if _, err := ParseRequest(fresh(), now); err != nil {
			t.Errorf("at %v: %v", now.Sub(testNow), err)
		}
	}
	var ae *Error
	if _, err := ParseRequest(fresh(), testNow.Add(time.Hour)); !errors.As(err, &ae) || ae.Code != CodeStale {
		t.Errorf("an old request: %v, want code %s", err, CodeStale)
	}

	// A console keeps a nonce through NonceExpires and may forget it after,
	// because only then does the request become stale
	q, err := ParseRequest(fresh(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRequest(fresh(), q.NonceExpires()); err != nil {
		t.Errorf("at NonceExpires: %v", err)
	}
	if _, err := ParseRequest(fresh(), q.NonceExpires().Add(time.Nanosecond)); !errors.As(err, &ae) || ae.Code != CodeStale {
		t.Errorf("after NonceExpires: %v, want code %s", err, CodeStale)
	}
}

func mustKey(k *ecdsa.PrivateKey, err error) *ecdsa.PrivateKey {
	if err != nil {
		panic(err)
	}
	return k
}

func TestUnsigned(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/v1/bundles", nil)
	var ae *Error
	if _, err := ParseRequest(r, testNow); !errors.As(err, &ae) || ae.Code != CodeUnauthenticated || !strings.Contains(err.Error(), "enroll") {
		t.Fatalf("got %v", err)
	}
}

func TestCheckBody(t *testing.T) {
	s := testSigner(t)
	q, err := ParseRequest(signed(t, s, "POST", "/api/v1/events", []byte("a")), testNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{nil, []byte("b"), []byte("a\n"), []byte("A")} {
		if q.CheckBody(b) == nil {
			t.Errorf("body %q accepted for a signature over %q", b, "a")
		}
	}
}

func TestSignerRefusesBadIdentity(t *testing.T) {
	s := testSigner(t)
	p384 := mustKey(ecdsa.GenerateKey(elliptic.P384(), rand.Reader))
	for name, bad := range map[string]*Signer{
		"no key":   {ID: testID},
		"P-384":    {ID: testID, Key: p384},
		"not v4":   {ID: "0b6a3f4e-2c1d-1e5f-8a9b-0c1d2e3f4a5b", Key: s.Key},
		"upper":    {ID: strings.ToUpper(testID), Key: s.Key},
		"no dashs": {ID: strings.ReplaceAll(testID, "-", ""), Key: s.Key},
	} {
		if err := bad.Sign(httptest.NewRequest("GET", "/", nil), nil); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}

func replaceNonce(input, nonce string) string {
	i := strings.Index(input, `nonce="`) + len(`nonce="`)
	j := i + strings.IndexByte(input[i:], '"')
	return input[:i] + nonce + input[j:]
}

func flip(sig string) string {
	b := []byte(sig)
	i := len("cyberboar=:") + 3
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

// answer signs a 202 to req as a console would
func answer(t *testing.T, console *ecdsa.PrivateKey, req *http.Request, status int, body []byte, now time.Time) *http.Response {
	t.Helper()
	q, err := ParseRequest(req, now)
	if err != nil {
		t.Fatal(err)
	}
	resp := &http.Response{StatusCode: status, Header: http.Header{}}
	if err := (&ResponseSigner{Key: console, Now: func() time.Time { return now }}).Sign(resp.Header, status, body, q); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestVerifyResponse(t *testing.T) {
	s := testSigner(t)
	console := newKey(t)
	req := signed(t, s, "POST", "https://console.example/api/v1/events", []byte("{}"))
	body := []byte(`{"accepted":0}` + "\n")
	good := answer(t, console, req, 202, body, testNow)
	if err := VerifyResponse(good, body, req, &console.PublicKey, testNow); err != nil {
		t.Fatal(err)
	}
	for _, now := range []time.Time{testNow.Add(MaxSkew), testNow.Add(-MaxSkew)} {
		if err := VerifyResponse(good, body, req, &console.PublicKey, now); err != nil {
			t.Errorf("at the window's edge (%v): %v", now.Sub(testNow), err)
		}
	}
	other := signed(t, s, "POST", "https://console.example/api/v1/events", []byte("{}"))
	input, sig := good.Header.Get("Signature-Input"), good.Header.Get("Signature")

	// Signed by the pinned key but naming another: the profile fixes keyid
	params := responseParams(testNow.Unix(), KeyID(&newKey(t).PublicKey))
	wrongID, err := signBase(console, responseBase(202, ContentDigest(body), strings.TrimPrefix(req.Header.Get("Signature"), "cyberboar="), params))
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		edit func(r *http.Response)
		body []byte
		req  *http.Request
		key  *ecdsa.PublicKey
		now  time.Time
	}{
		"other key":         {key: &newKey(t).PublicKey},
		"no key":            {key: nil},
		"other request":     {req: other},
		"unsigned request":  {req: httptest.NewRequest("POST", "/api/v1/events", nil)},
		"other status":      {edit: func(r *http.Response) { r.StatusCode = 200 }},
		"other body":        {body: []byte(`{"accepted":1}` + "\n")},
		"no body":           {body: []byte{}},
		"too old":           {now: testNow.Add(MaxSkew + time.Second)},
		"from the future":   {now: testNow.Add(-MaxSkew - time.Second)},
		"unsigned":          {edit: func(r *http.Response) { r.Header.Del("Signature"); r.Header.Del("Signature-Input") }},
		"no input":          {edit: func(r *http.Response) { r.Header.Del("Signature-Input") }},
		"two signatures":    {edit: func(r *http.Response) { r.Header.Add("Signature", sig) }},
		"no digest":         {edit: func(r *http.Response) { r.Header.Del("Content-Digest") }},
		"flipped signature": {edit: func(r *http.Response) { r.Header.Set("Signature", flip(sig)) }},
		"request profile": {edit: func(r *http.Response) {
			r.Header.Set("Signature-Input", strings.Replace(input, "console/v1", "endpoint/v1", 1))
		}},
		"leading zero": {edit: func(r *http.Response) {
			r.Header.Set("Signature-Input", strings.Replace(input, "created=", "created=0", 1))
		}},
		"keyid of another key": {edit: func(r *http.Response) {
			r.Header.Set("Signature-Input", "cyberboar="+params)
			r.Header.Set("Signature", "cyberboar="+wrongID)
		}},
		"other keyid": {edit: func(r *http.Response) {
			r.Header.Set("Signature-Input", strings.Replace(input, `keyid="`, `keyid="0`, 1)[:len(input)+1])
		}},
	} {
		resp := &http.Response{StatusCode: 202, Header: good.Header.Clone()}
		if tc.edit != nil {
			tc.edit(resp)
		}
		b, r, key, now := body, req, &console.PublicKey, testNow
		if tc.body != nil {
			b = tc.body
		}
		if tc.req != nil {
			r = tc.req
		}
		if name == "other key" || name == "no key" {
			key = tc.key
		}
		if !tc.now.IsZero() {
			now = tc.now
		}
		if err := VerifyResponse(resp, b, r, key, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPublicKeyEncoding(t *testing.T) {
	pub := &newKey(t).PublicKey
	enc, err := EncodePublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodePublicKey(enc)
	if err != nil || !got.Equal(pub) {
		t.Fatalf("round trip: %v", err)
	}
	p384, _ := x509.MarshalPKIXPublicKey(&mustKey(ecdsa.GenerateKey(elliptic.P384(), rand.Reader)).PublicKey)
	for _, bad := range []string{"", "AAAA", enc + "AAAA", strings.TrimRight(enc, "="), "!" + enc[1:],
		enc[:20] + "\n" + enc[20:], enc[:20] + "\r\n" + enc[20:], "\n" + enc, enc + "\n",
		base64.StdEncoding.EncodeToString(p384)} {
		if _, err := DecodePublicKey(bad); err == nil {
			t.Errorf("%q decoded", bad)
		}
	}
	if _, err := EncodePublicKey(&mustKey(ecdsa.GenerateKey(elliptic.P384(), rand.Reader)).PublicKey); err == nil {
		t.Error("encoded a P-384 key")
	}
	if id := KeyID(pub); len(id) != 64 || id != KeyID(got) || id == KeyID(&newKey(t).PublicKey) {
		t.Errorf("key ID %q", id)
	}
}

func TestTokens(t *testing.T) {
	a, ha := NewToken()
	b, hb := NewToken()
	if a == b || bytes.Equal(ha, hb) {
		t.Fatal("two tokens are the same")
	}
	if !ValidToken(a) || !strings.HasPrefix(a, "cyberboar_enroll_") {
		t.Fatalf("token %q", a)
	}
	if sum := sha256.Sum256([]byte(a)); !bytes.Equal(HashToken(a), ha) || !bytes.Equal(ha, sum[:]) {
		t.Fatal("hash differs")
	}
	for _, bad := range []string{"", a + "A", a[:len(a)-1], strings.ToUpper(a), "x" + a, a + "\n"} {
		if ValidToken(bad) {
			t.Errorf("%q is valid", bad)
		}
	}
}

// issue makes a client certificate as a console would
// edit changes the template first
func issue(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, pub *ecdsa.PublicKey, edit func(*x509.Certificate)) []byte {
	t.Helper()
	u, _ := url.Parse(EndpointURI(testID))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: testID},
		URIs:         []*url.URL{u},
		NotBefore:    testNow.Add(-time.Minute),
		NotAfter:     testNow.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if edit != nil {
		edit(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, pub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCheckCertificate(t *testing.T) {
	caKey := newKey(t)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour * 48),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	key := newKey(t)
	good := issue(t, ca, caKey, &key.PublicKey, nil)
	chain, err := CheckCertificate(good, testID, &key.PublicKey, testNow)
	if err != nil || len(chain) != 1 {
		t.Fatalf("good certificate: %v", err)
	}
	if _, err := CheckCertificate(append(good, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...), testID, &key.PublicKey, testNow); err != nil {
		t.Errorf("with an intermediate: %v", err)
	}
	other, _ := url.Parse(EndpointURI("1b6a3f4e-2c1d-4e5f-8a9b-0c1d2e3f4a5b"))
	for name, tc := range map[string]struct {
		pem []byte
		now time.Time
	}{
		"other key":         {pem: issue(t, ca, caKey, &newKey(t).PublicKey, nil)},
		"other id":          {pem: issue(t, ca, caKey, &key.PublicKey, func(c *x509.Certificate) { c.URIs = []*url.URL{other} })},
		"two ids":           {pem: issue(t, ca, caKey, &key.PublicKey, func(c *x509.Certificate) { c.URIs = append(c.URIs, other) })},
		"no id":             {pem: issue(t, ca, caKey, &key.PublicKey, func(c *x509.Certificate) { c.URIs = nil })},
		"server only":       {pem: issue(t, ca, caKey, &key.PublicKey, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} })},
		"no usage":          {pem: issue(t, ca, caKey, &key.PublicKey, func(c *x509.Certificate) { c.ExtKeyUsage = nil })},
		"a CA":              {pem: issue(t, ca, caKey, &key.PublicKey, func(c *x509.Certificate) { c.BasicConstraintsValid, c.IsCA = true, true })},
		"expired":           {pem: good, now: testNow.Add(25 * time.Hour)},
		"not yet":           {pem: good, now: testNow.Add(-time.Minute - MaxSkew - time.Second)},
		"empty":             {pem: nil},
		"junk after":        {pem: append(bytes.Clone(good), "junk"...)},
		"private key":       {pem: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})},
		"too many":          {pem: bytes.Repeat(good, 5)},
		"too large":         {pem: bytes.Repeat([]byte("\n"), MaxCertificatePEM+1)},
		"with headers":      {pem: bytes.Replace(good, []byte("-----\n"), []byte("-----\nProc-Type: 4,ENCRYPTED\n\n"), 1)},
		"not a certificate": {pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")})},
	} {
		now := testNow
		if !tc.now.IsZero() {
			now = tc.now
		}
		if _, err := CheckCertificate(tc.pem, testID, &key.PublicKey, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
