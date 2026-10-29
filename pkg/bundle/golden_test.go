package bundle_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/pkg/brand"
	"cyberboar.dev/cyberboar/pkg/bundle"
	"cyberboar.dev/cyberboar/pkg/sign"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/protocol")

// goldenClock is the time the golden files are made for (docs/protocol); the
// golden serial is its Unix time, as `sign --serial $(date +%s)` would write.
var goldenClock = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// goldenBundles defines the generated fixtures and their signature headers.
var goldenBundles = map[string]sign.Header{
	"bundle-baseline.json":           {Serial: 1790856000, Expires: goldenClock.AddDate(0, 0, 90)},
	"bundle-reject-expired.json":     {Serial: 1790856001, Expires: goldenClock},
	"bundle-reject-rollback.json":    {Serial: 1790855999, Expires: goldenClock.AddDate(0, 0, 90)},
	"bundle-reject-same-serial.json": {Serial: 1790856000, Expires: goldenClock.AddDate(0, 0, 91)},
	"bundle-never-expires.json":      {Serial: 1790856002},
}

// The golden bundles in testdata/protocol are what this package builds from
// examples/baseline.yaml signed with the test key. Other
// implementations of the protocol test against them (docs/protocol), so a
// change here is a change to the protocol.
func TestGoldenBundle(t *testing.T) {
	priv, err := sign.LoadPrivate("../../testdata/protocol/insecure-test.key")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := sign.LoadPublic("../../testdata/protocol/insecure-test.pub")
	if err != nil {
		t.Fatal(err)
	}
	data := readBaseline(t)
	golden := map[string][]byte{}
	for file, h := range goldenBundles {
		dir := t.TempDir()
		write(t, dir, "baseline.yaml", data)
		sig, err := sign.Sign(priv, "baseline", data, h)
		if err != nil {
			t.Fatal(err)
		}
		write(t, dir, "baseline.yaml"+sign.SigSuffix, []byte(sig))
		set, err := bundle.LoadDir(dir, pub)
		if err != nil {
			t.Fatal(err)
		}
		b, ok := set.Bundle("baseline")
		if !ok {
			t.Fatalf("%s: baseline not served: %v", file, set.Sources[0].Err)
		}
		if set.Sources[0].Header != h {
			t.Errorf("%s: header %+v, want %+v", file, set.Sources[0].Header, h)
		}
		golden[file] = b.Body
		if file == "bundle-baseline.json" {
			golden[file+".etag"] = []byte(b.ETag + "\n")
		}
	}
	var envelope bundle.Envelope
	if err := json.Unmarshal(golden["bundle-baseline.json"], &envelope); err != nil {
		t.Fatal(err)
	}
	wrongAPI := envelope
	wrongAPI.APIVersion = brand.APIGroup + "/unsupported"
	_, raw, err := sign.Parse([]byte(envelope.Signature))
	if err != nil {
		t.Fatal(err)
	}
	envelope.Signature = base64.StdEncoding.EncodeToString(raw) + "\n"
	for name, invalid := range map[string]bundle.Envelope{
		"bundle-reject-api-version.json": wrongAPI,
		"bundle-reject-signature.json":   envelope,
	} {
		body, err := json.Marshal(invalid)
		if err != nil {
			t.Fatal(err)
		}
		golden[name] = append(body, '\n')
	}
	for name, want := range golden {
		path := filepath.Join("../../testdata/protocol", name)
		if *update {
			if err := os.WriteFile(path, want, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from what this package builds; if the protocol changed on purpose, run go test -update and describe the change in docs/protocol", name)
		}
	}
}

// A console configured with a key serves only policies signed with it.
func TestLoadDirRequiresSignatures(t *testing.T) {
	priv, _ := sign.LoadPrivate("../../testdata/protocol/insecure-test.key")
	pub, _ := sign.LoadPublic("../../testdata/protocol/insecure-test.pub")
	data := readBaseline(t)
	for name, sig := range map[string]string{
		"unsigned":       "",
		"edited":         signed(t, priv, "baseline", append(bytes.Clone(data), '#')),
		"renamed":        signed(t, priv, "other", data),
		"not base64":     "!!!\n",
		"truncated sig":  signed(t, priv, "baseline", data)[:60],
		"bare signature": "",
	} {
		dir := t.TempDir()
		policy := data
		if name == "bare signature" {
			policy, sig = invalidSignatureBundle(t)
		}
		write(t, dir, "baseline.yaml", policy)
		if sig != "" {
			write(t, dir, "baseline.yaml"+sign.SigSuffix, []byte(sig))
		}
		set, err := bundle.LoadDir(dir, pub)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := set.Bundle("baseline"); ok || set.Sources[0].Err == nil {
			t.Errorf("%s: served", name)
		}
	}
}

func signed(t *testing.T, priv ed25519.PrivateKey, name string, data []byte) string {
	t.Helper()
	sig, err := sign.Sign(priv, name, data, goldenBundles["bundle-baseline.json"])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// invalidSignatureBundle reads a fixture whose signature is missing its headers.
func invalidSignatureBundle(t *testing.T) (policy []byte, sig string) {
	t.Helper()
	body, err := os.ReadFile("../../testdata/protocol/bundle-reject-signature.json")
	if err != nil {
		t.Fatal(err)
	}
	var env bundle.Envelope
	if err := json.Unmarshal(body, &env); err != nil || env.Name != "baseline" {
		t.Fatalf("bundle-reject-signature.json is not a bundle of baseline: %v", err)
	}
	return []byte(env.Policy), env.Signature
}
