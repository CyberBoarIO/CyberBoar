package pull

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/internal/endpoint/enroll"
	"cyberboar.dev/cyberboar/internal/endpoint/httpsclient"
	"cyberboar.dev/cyberboar/internal/endpoint/keystore"
	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/internal/protocoltest"
	"cyberboar.dev/cyberboar/pkg/brand"
	"cyberboar.dev/cyberboar/pkg/bundle"
	"cyberboar.dev/cyberboar/pkg/sign"
)

type fixture struct {
	dir, out string
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
	policy   []byte
	console  *protocoltest.Console
	ca       string // trusts the console's certificate
}

func setup(t *testing.T, requireSigned bool) *fixture {
	t.Helper()
	f := &fixture{dir: t.TempDir()}
	kp, kpub := filepath.Join(t.TempDir(), "k"), filepath.Join(t.TempDir(), "k.pub")
	if err := sign.Keygen(kp, kpub); err != nil {
		t.Fatal(err)
	}
	f.priv, _ = sign.LoadPrivate(kp)
	f.pub, _ = sign.LoadPublic(kpub)
	var err error
	if f.policy, err = os.ReadFile("../../../examples/baseline.yaml"); err != nil {
		t.Fatal(err)
	}
	f.write(t, f.policy, signAt(t, f.priv, "baseline", f.policy, 100))
	var pub ed25519.PublicKey
	if requireSigned {
		pub = f.pub
	}
	f.console = protocoltest.NewStatic(t, f.dir, pub)
	f.ca = f.console.CAFile(t)
	f.out = filepath.Join(t.TempDir(), "policy.yaml")
	return f
}

func (f *fixture) write(t *testing.T, policy []byte, sig string) {
	t.Helper()
	os.WriteFile(filepath.Join(f.dir, "baseline.yaml"), policy, 0o600)
	os.WriteFile(filepath.Join(f.dir, "baseline.yaml.sig"), []byte(sig), 0o600)
}

func (f *fixture) opts() Options {
	return Options{Server: f.console.URL, Name: "baseline", Out: f.out, PublicKey: f.pub,
		TLS: httpsclient.TLS{CAFile: f.ca}, Now: func() time.Time { return clock }}
}

// clock is the time of every test pull, and of the golden files
// (docs/protocol).
var clock = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// signAt signs a policy with a serial, valid for 90 days after clock.
func signAt(t *testing.T, priv ed25519.PrivateKey, name string, policy []byte, serial uint64) string {
	t.Helper()
	sig, err := sign.Sign(priv, name, policy, sign.Header{Serial: serial, Expires: clock.AddDate(0, 0, 90)})
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestPullInstallsSignedPolicy(t *testing.T) {
	f := setup(t, true)
	changed, err := Once(context.Background(), f.opts())
	if err != nil || !changed {
		t.Fatalf("changed %v, err %v", changed, err)
	}
	got, _ := os.ReadFile(f.out)
	sig, _ := os.ReadFile(f.out + sign.SigSuffix)
	if _, err := sign.Verify(f.pub, "baseline", got, sig); !bytes.Equal(got, f.policy) || err != nil {
		t.Fatal("installed policy or signature is wrong")
	}
	if changed, err := Once(context.Background(), f.opts()); err != nil || changed {
		t.Errorf("second pull: changed %v, err %v", changed, err)
	}
}

// JSON escaping must fit the bundle limit even at the policy size limit.
func TestPullInstallsMaximumSizePolicy(t *testing.T) {
	for _, tc := range []struct {
		name, padding string
		authenticated bool
	}{
		{"static host/HTML", "<>&", false},
		{"enrolled console/HTML", "<>&", true},
		{"static host/control bytes", "\x01", false},
		{"enrolled console/control bytes", "\x01", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t, true)
			data := append(bytes.Clone(f.policy), []byte("\n# ")...)
			padding := bytes.Repeat([]byte(tc.padding), policy.MaxSize/len(tc.padding)+1)
			data = append(data, padding[:policy.MaxSize-len(data)-1]...)
			data = append(data, '\n')
			f.write(t, data, signAt(t, f.priv, "baseline", data, 101))
			f.console.Reload(t)
			o := f.opts()
			if tc.authenticated {
				c := protocoltest.New(t, f.dir, f.pub)
				tc := httpsclient.TLS{CAFile: c.CAFile(t)}
				ep, _, err := enroll.Once(context.Background(), enroll.Options{
					Server: c.URL, Token: c.Token("baseline", 1), StateDir: t.TempDir(),
					TLS: tc, KeyStorage: keystore.File, Version: "v1",
				})
				if err != nil {
					t.Fatal(err)
				}
				o.Server, o.TLS = c.URL, tc
				o.Client, err = ep.Client(tc)
				if err != nil {
					t.Fatal(err)
				}
			}
			if changed, err := Once(context.Background(), o); err != nil || !changed {
				t.Fatalf("maximum-size policy: changed %v, err %v", changed, err)
			}
			got, err := os.ReadFile(f.out)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("installed policy differs: %v", err)
			}
			sig, err := sign.ReadSig(f.out)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := sign.Verify(f.pub, "baseline", got, sig); err != nil {
				t.Fatalf("installed signature: %v", err)
			}
		})
	}
}

func TestPullRejectsOversizedBundle(t *testing.T) {
	f := setup(t, true)
	if _, err := Once(context.Background(), f.opts()); err != nil {
		t.Fatal(err)
	}
	oldSig, err := sign.ReadSig(f.out)
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte(" "), bundle.MaxSize+1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()
	o := f.opts()
	o.Server, o.Client = srv.URL, srv.Client()
	if changed, err := Once(context.Background(), o); changed || err == nil || !strings.Contains(err.Error(), "bundle is larger than") {
		t.Fatalf("oversized bundle: changed %v, err %v", changed, err)
	}
	if got, err := os.ReadFile(f.out); err != nil || !bytes.Equal(got, f.policy) {
		t.Fatalf("installed policy changed: %v", err)
	}
	if got, err := sign.ReadSig(f.out); err != nil || !bytes.Equal(got, oldSig) {
		t.Fatalf("installed signature changed: %v", err)
	}
}

func TestPullInstallsMinimumVersion(t *testing.T) {
	f := setup(t, true)
	if _, err := Once(context.Background(), f.opts()); err != nil {
		t.Fatal(err)
	}
	data := []byte("apiVersion: " + brand.APIVersion + "\nkind: Policy\nmetadata: {name: baseline}\nspec: {minimumVersion: 999.0.0}\n")
	f.write(t, data, signAt(t, f.priv, "baseline", data, 101))
	f.console.Reload(t)
	changed, err := Once(context.Background(), f.opts())
	if err != nil || !changed {
		t.Fatalf("new version floor was not installed: changed %v, err %v", changed, err)
	}
	got, err := os.ReadFile(f.out)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("installed policy differs: %s (%v)", got, err)
	}
	f.write(t, f.policy, signAt(t, f.priv, "baseline", f.policy, 100))
	f.console.Reload(t)
	if _, err := Once(context.Background(), f.opts()); err == nil {
		t.Fatal("lower-serial policy removed the version floor")
	}
	got, err = os.ReadFile(f.out)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("rollback changed the installed floor: %s (%v)", got, err)
	}
}

// Whatever goes wrong, the installed policy stays as it was.
func TestPullKeepsLastGoodPolicy(t *testing.T) {
	f := setup(t, false) // a console that serves anything: the endpoint must check
	if _, err := Once(context.Background(), f.opts()); err != nil {
		t.Fatal(err)
	}
	good, _ := os.ReadFile(f.out)
	check := func(name string, o Options) {
		t.Helper()
		f.console.Reload(t)
		if _, err := Once(context.Background(), o); err == nil {
			t.Errorf("%s: installed", name)
		}
		if got, _ := os.ReadFile(f.out); !bytes.Equal(got, good) {
			t.Fatalf("%s: the installed policy changed", name)
		}
	}
	// A policy edited after signing.
	edited := append(bytes.Clone(f.policy), "# weakened\n"...)
	f.write(t, edited, signAt(t, f.priv, "baseline", f.policy, 101))
	check("edited policy", f.opts())
	// Older, or the same serial with other contents.
	f.write(t, edited, signAt(t, f.priv, "baseline", edited, 99))
	check("rollback", f.opts())
	f.write(t, edited, signAt(t, f.priv, "baseline", edited, 100))
	check("same serial", f.opts())
	// Expired, or missing signature headers
	exp, _ := sign.Sign(f.priv, "baseline", edited, sign.Header{Serial: 101, Expires: clock})
	f.write(t, edited, exp)
	check("expired", f.opts())
	f.write(t, edited, string(bareSignature(t, f.priv, "baseline", edited)))
	check("bare signature", f.opts())
	// Signed by another key.
	kp, kpub := filepath.Join(t.TempDir(), "o"), filepath.Join(t.TempDir(), "o.pub")
	sign.Keygen(kp, kpub)
	other, _ := sign.LoadPrivate(kp)
	f.write(t, edited, signAt(t, other, "baseline", edited, 101))
	check("other key", f.opts())
	// Unsigned.
	os.Remove(filepath.Join(f.dir, "baseline.yaml.sig"))
	check("unsigned", f.opts())
	// Wrong name, unknown bundle, plain http off-host, no key.
	o := f.opts()
	o.Name = "strict"
	check("unknown bundle", o)
	o = f.opts()
	o.Server = "http://console.example"
	check("plain http", o)
	o = f.opts()
	o.Server = strings.Replace(f.console.URL, "https://", "http://", 1)
	check("plain http to loopback", o)
	o = f.opts()
	o.TLS = httpsclient.TLS{}
	check("unverified certificate", o)
	o = f.opts()
	o.PublicKey = nil
	check("no key", o)
}

func TestCheckRejectsInvalidBundles(t *testing.T) {
	f := setup(t, true)
	resp, err := f.console.Client().Get(f.console.URL + "/api/v1/bundles/baseline")
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	body.ReadFrom(resp.Body)
	resp.Body.Close()
	if _, _, _, err := Check(body.Bytes(), "baseline", f.pub, clock); err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}
	for name, b := range map[string]string{
		"wrong name":    strings.Replace(body.String(), `"name":"baseline"`, `"name":"other"`, 1),
		"wrong hash":    strings.Replace(body.String(), `"policySha256":"`, `"policySha256":"0`, 1),
		"extra field":   strings.Replace(body.String(), `{"apiVersion"`, `{"x":1,"apiVersion"`, 1),
		"wrong kind":    strings.Replace(body.String(), `"kind":"PolicyBundle"`, `"kind":"Policy"`, 1),
		"not json":      "nope",
		"no signature":  strings.Replace(body.String(), `"signature":"`, `"x":"`, 1),
		"trailing data": body.String() + `{"junk":1}`,
	} {
		if _, _, _, err := Check([]byte(b), "baseline", f.pub, clock); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The protocol's golden bundles (docs/protocol): bundle-baseline.json is
// accepted with its key and only with it, at the golden clock and not after
// it expires; the reject-* bundles are refused as the protocol says.
func TestGoldenBundles(t *testing.T) {
	read := func(name string) []byte {
		t.Helper()
		body, err := os.ReadFile("../../../testdata/protocol/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	pub, err := sign.LoadPublic("../../../testdata/protocol/insecure-test.pub")
	if err != nil {
		t.Fatal(err)
	}
	baseline := read("bundle-baseline.json")
	data, sig, h, err := Check(baseline, "baseline", pub, clock)
	if err != nil {
		t.Fatalf("golden bundle rejected: %v", err)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if _, _, _, err := Check(baseline, "baseline", other, clock); err == nil {
		t.Error("golden bundle accepted with another key")
	}
	if _, _, _, err := Check(baseline, "baseline", pub, h.Expires); err == nil {
		t.Error("golden bundle accepted once expired")
	}
	if _, _, _, err := Check(read("bundle-reject-expired.json"), "baseline", pub, clock); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("bundle-reject-expired.json: %v", err)
	}
	if _, _, nh, err := Check(read("bundle-never-expires.json"), "baseline", pub, clock.AddDate(500, 0, 0)); err != nil || nh.Serial != 1790856002 {
		t.Errorf("bundle-never-expires.json: %v", err)
	}
	for _, name := range []string{"bundle-reject-api-version.json", "bundle-reject-signature.json"} {
		if _, _, _, err := Check(read(name), "baseline", pub, clock); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	var env bundle.Envelope
	if err := json.Unmarshal(read("bundle-reject-signature.json"), &env); err != nil {
		t.Fatal(err)
	}
	if _, err := sign.Verify(pub, "baseline", []byte(env.Policy), []byte(env.Signature)); !errors.Is(err, sign.ErrBadSignature) {
		t.Errorf("bundle-reject-signature.json's signature: %v", err)
	}
	// The rollback and same-serial bundles are valid on their own: a fresh
	// endpoint installs them. One that installed bundle-baseline.json
	// refuses them and keeps it.
	for _, name := range []string{"bundle-reject-rollback.json", "bundle-reject-same-serial.json"} {
		d, s, hh, err := Check(read(name), "baseline", pub, clock)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		fresh := filepath.Join(t.TempDir(), "policy.yaml")
		if changed, err := install(fresh, d, s, hh); err != nil || !changed {
			t.Errorf("%s on a fresh endpoint: changed %v, err %v", name, changed, err)
		}
		out := filepath.Join(t.TempDir(), "policy.yaml")
		if _, err := install(out, data, sig, h); err != nil {
			t.Fatal(err)
		}
		if changed, err := install(out, d, s, hh); err == nil || changed {
			t.Errorf("%s after bundle-baseline.json: changed %v, err %v", name, changed, err)
		}
		if got, _ := os.ReadFile(out + sign.SigSuffix); !bytes.Equal(got, sig) {
			t.Errorf("%s: the installed signature changed", name)
		}
		if changed, err := install(out, data, sig, h); err != nil || changed {
			t.Errorf("bundle-baseline.json again: changed %v, err %v", changed, err)
		}
	}
}

// The rollback floor is zero only when no signature is installed
// Invalid signatures block installation; interrupted installs can be completed
func TestInstalledSerial(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pol := []byte("policy\n")
	sig := []byte(signAt(t, priv, "baseline", pol, 7))
	h := sign.Header{Serial: 7, Expires: clock.AddDate(0, 0, 90)}

	out := filepath.Join(t.TempDir(), "policy.yaml")
	os.WriteFile(out, []byte("old\n"), 0o644)
	if n, err := installedSerial(out); n != 0 || err != nil {
		t.Errorf("no signature: %d, %v", n, err)
	}
	if changed, err := install(out, pol, sig, h); err != nil || !changed {
		t.Fatalf("initial install: changed %v, err %v", changed, err)
	}
	if n, err := installedSerial(out); n != 7 || err != nil {
		t.Errorf("installed signature: %d, %v", n, err)
	}

	// Interrupted: the new signature is in place, the old policy too.
	os.WriteFile(out, []byte("old\n"), 0o644)
	if changed, err := install(out, pol, sig, h); err != nil || !changed {
		t.Fatalf("completing: changed %v, err %v", changed, err)
	}
	if got, _ := os.ReadFile(out); !bytes.Equal(got, pol) {
		t.Error("the interrupted install wasn't completed")
	}

	for name, junk := range map[string]string{"garbage": "junk\n", "empty": "", "huge": strings.Repeat("A", 1000),
		"missing headers": string(bareSignature(t, priv, "baseline", pol))} {
		os.WriteFile(out+sign.SigSuffix, []byte(junk), 0o644)
		if _, err := installedSerial(out); err == nil {
			t.Errorf("%s: no error", name)
		}
		if changed, err := install(out, pol, sig, h); err == nil || changed {
			t.Errorf("%s: installed over it", name)
		}
	}
}

// bareSignature removes the headers from an otherwise valid signature
func bareSignature(t *testing.T, priv ed25519.PrivateKey, name string, policy []byte) []byte {
	t.Helper()
	_, raw, err := sign.Parse([]byte(signAt(t, priv, name, policy, 1)))
	if err != nil {
		t.Fatal(err)
	}
	return []byte(base64.StdEncoding.EncodeToString(raw) + "\n")
}

// A console's error text reaches the operator's terminal, so control
// characters in it are escaped rather than printed
func TestConsoleErrorTextIsEscaped(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "\x1b]0;owned\x07\x1b[2Jcleared", http.StatusInternalServerError)
	}))
	defer srv.Close()
	_, err := Once(context.Background(), Options{Server: srv.URL, Name: "baseline", Out: filepath.Join(t.TempDir(), "policy.yaml"),
		PublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize), Client: srv.Client()})
	if err == nil || strings.ContainsAny(err.Error(), "\x1b\x07") || !strings.Contains(err.Error(), `\x1b`) {
		t.Fatalf("error = %q, want the control characters escaped", err)
	}
}
