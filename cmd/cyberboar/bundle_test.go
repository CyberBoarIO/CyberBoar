package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/internal/protocoltest"
	"cyberboar.dev/cyberboar/pkg/bundle"
	"cyberboar.dev/cyberboar/pkg/sign"
)

// Bundling a signed policy produces the expected golden bundle
// Pull downloads and verifies that bundle from a static HTTPS server,
// then writes the policy locally
func TestBundleStaticSite(t *testing.T) {
	now := fixedClock(goldenClock)
	dir := t.TempDir()
	pols, site := filepath.Join(dir, "policies"), filepath.Join(dir, "site")
	os.MkdirAll(pols, 0o755)
	data, _ := os.ReadFile(baseline)
	priv, err := sign.LoadPrivate("../../testdata/protocol/insecure-test.key")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(pols, "baseline.yaml"), data, 0o644)
	os.WriteFile(filepath.Join(pols, "baseline.yaml.sig"), []byte(goldenSig(t, priv, data)), 0o644)
	pub := "../../testdata/protocol/insecure-test.pub"
	env := func(k string) string { return map[string]string{"HOME": dir}[k] }
	var out, errb bytes.Buffer
	if code := runAt(now, []string{"bundle", "-pubkey", pub, "-out", site, pols}, strings.NewReader(""), &out, &errb, env); code != 0 {
		t.Fatalf("bundle exit %d: %s", code, errb.String())
	}
	got, _ := os.ReadFile(bundlePath(site, "baseline"))
	want, _ := os.ReadFile("../../testdata/protocol/bundle-baseline.json")
	if !bytes.Equal(got, want) {
		t.Fatal("the written bundle differs from the protocol's golden bundle")
	}

	static := httptest.NewTLSServer(http.FileServer(http.Dir(site)))
	defer static.Close()
	installed := filepath.Join(dir, "installed", "policy.yaml")
	if code := runAt(now, []string{"pull", "-server", static.URL, "-name", "baseline", "-out", installed, "-pubkey", pub, "-ca", protocoltest.CAFile(t, static)},
		strings.NewReader(""), &out, &errb, env); code != 0 {
		t.Fatalf("pull from a static site: exit %d: %s", code, errb.String())
	}
	if got, _ := os.ReadFile(installed); !bytes.Equal(got, data) {
		t.Fatal("pull installed something else")
	}

	// Once the signature has expired, nothing is written
	now = fixedClock(goldenClock.AddDate(0, 0, 90))
	os.RemoveAll(site)
	if code := runAt(now, []string{"bundle", "-pubkey", pub, "-out", site, pols}, strings.NewReader(""), &out, &errb, env); code != 1 || !strings.Contains(errb.String(), "expired") {
		t.Fatalf("bundle of an expired policy: exit %d: %s", code, errb.String())
	}
	if _, err := os.Stat(site); !os.IsNotExist(err) {
		t.Error("an expired bundle was written")
	}
}

// goldenClock is the time the protocol's golden files are made for (docs/protocol)
var goldenClock = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// goldenSig signs a policy as testdata/protocol/bundle-baseline.json is
func goldenSig(t *testing.T, priv ed25519.PrivateKey, data []byte) string {
	t.Helper()
	sig, err := sign.Sign(priv, "baseline", data, sign.Header{Serial: 1790856000, Expires: goldenClock.AddDate(0, 0, 90)})
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// One policy that isn't signed with the key means nothing is written
func TestBundleAllOrNothing(t *testing.T) {
	dir := t.TempDir()
	pols, site := filepath.Join(dir, "policies"), filepath.Join(dir, "site")
	os.MkdirAll(pols, 0o755)
	data, _ := os.ReadFile(baseline)
	priv, _ := sign.LoadPrivate("../../testdata/protocol/insecure-test.key")
	os.WriteFile(filepath.Join(pols, "baseline.yaml"), data, 0o644)
	os.WriteFile(filepath.Join(pols, "baseline.yaml.sig"), []byte(goldenSig(t, priv, data)), 0o644)
	other := bytes.Replace(data, []byte("name: baseline"), []byte("name: other"), 1)
	os.WriteFile(filepath.Join(pols, "other.yaml"), other, 0o644) // unsigned
	env := func(k string) string { return map[string]string{"HOME": dir}[k] }
	var out, errb bytes.Buffer
	code := runAt(fixedClock(goldenClock), []string{"bundle", "-pubkey", "../../testdata/protocol/insecure-test.pub", "-out", site, pols}, strings.NewReader(""), &out, &errb, env)
	if code != 1 || !strings.Contains(errb.String(), "other.yaml") {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if _, err := os.Stat(site); !os.IsNotExist(err) {
		t.Error("something was written")
	}
	for _, args := range [][]string{
		{"bundle", "-out", site, pols},                          // no key
		{"bundle", "-pubkey", "k.pub", pols},                    // no -out
		{"bundle", "-pubkey", "k.pub", "-out", site},            // no directory
		{"bundle", "-pubkey", "k.pub", "-out", site, pols, "x"}, // two directories
	} {
		if code := run(args, strings.NewReader(""), &out, &errb, env); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

// signedPolicies writes baseline under each name, signed with the protocol's test key.
func signedPolicies(t *testing.T, dir string, names ...string) {
	t.Helper()
	os.MkdirAll(dir, 0o755)
	data, _ := os.ReadFile(baseline)
	priv, err := sign.LoadPrivate("../../testdata/protocol/insecure-test.key")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		p := bytes.Replace(data, []byte("name: baseline"), []byte("name: "+n), 1)
		os.WriteFile(filepath.Join(dir, n+".yaml"), p, 0o644)
		writeSig(t, priv, filepath.Join(dir, n+".yaml"), n, p)
	}
}

// writeSig signs policy data as name, valid for 90 days from the current
// time, and writes the signature next to path
func writeSig(t *testing.T, priv ed25519.PrivateKey, path, name string, data []byte) {
	t.Helper()
	sig, err := sign.Sign(priv, name, data, sign.Header{Serial: 1, Expires: time.Now().AddDate(0, 0, 90).Truncate(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".sig", []byte(sig), 0o644); err != nil {
		t.Fatal(err)
	}
}

func bundleSite(t *testing.T, pols, site string) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run([]string{"bundle", "-pubkey", "../../testdata/protocol/insecure-test.pub", "-out", site, pols},
		strings.NewReader(""), &out, &errb, func(string) string { return "" })
	return code, out.String() + errb.String()
}

func siteFiles(t *testing.T, site string) []string {
	t.Helper()
	entries, _ := os.ReadDir(bundlePath(site, ""))
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// Removing a policy file removes its generated bundle
// Files not generated by the command are preserved
func TestBundlePrunesRemovedPolicies(t *testing.T) {
	dir := t.TempDir()
	pols, site := filepath.Join(dir, "policies"), filepath.Join(dir, "site")
	signedPolicies(t, pols, "alpha", "beta")
	if code, out := bundleSite(t, pols, site); code != 0 {
		t.Fatalf("first run: %d %s", code, out)
	}
	os.WriteFile(bundlePath(site, "index.html"), []byte("mine"), 0o644)
	os.WriteFile(bundlePath(site, ".hidden"), []byte("mine"), 0o644)
	os.Remove(filepath.Join(pols, "beta.yaml"))
	os.Remove(filepath.Join(pols, "beta.yaml.sig"))
	code, out := bundleSite(t, pols, site)
	if code != 0 || !strings.Contains(out, "removed") {
		t.Fatalf("second run: %d %s", code, out)
	}
	if got := strings.Join(siteFiles(t, site), " "); got != ".hidden alpha index.html" {
		t.Errorf("site holds %q, want .hidden alpha index.html", got)
	}
	// No policies at all is an error, never an empty site.
	os.Remove(filepath.Join(pols, "alpha.yaml"))
	os.Remove(filepath.Join(pols, "alpha.yaml.sig"))
	if code, _ := bundleSite(t, pols, site); code != 1 || !slices.Contains(siteFiles(t, site), "alpha") {
		t.Errorf("an empty policy directory: exit %d, site %v", code, siteFiles(t, site))
	}
}

// A write that fails leaves the site exactly as it was
func TestBundleFailedWriteChangesNothing(t *testing.T) {
	dir := t.TempDir()
	pols, site := filepath.Join(dir, "policies"), filepath.Join(dir, "site")
	signedPolicies(t, pols, "alpha")
	bundleSite(t, pols, site)
	before, _ := os.ReadFile(bundlePath(site, "alpha"))

	signedPolicies(t, pols, "beta")
	data, _ := os.ReadFile(filepath.Join(pols, "alpha.yaml"))
	os.WriteFile(filepath.Join(pols, "alpha.yaml"), append(data, "# changed\n"...), 0o644)
	priv, _ := sign.LoadPrivate("../../testdata/protocol/insecure-test.key")
	data, _ = os.ReadFile(filepath.Join(pols, "alpha.yaml"))
	writeSig(t, priv, filepath.Join(pols, "alpha.yaml"), "alpha", data)
	pub, err := sign.LoadPublic("../../testdata/protocol/insecure-test.pub")
	if err != nil {
		t.Fatal(err)
	}
	set, err := bundle.LoadDir(pols, pub)
	if err != nil {
		t.Fatal(err)
	}
	failBeta := func(dir, name string, data []byte) (string, error) {
		if name == "beta" {
			return "", errors.New("disk full")
		}
		return stage(dir, name, data)
	}
	if err := publish(site, set.Bundles(), failBeta, io.Discard); err == nil || !strings.Contains(err.Error(), "nothing published") {
		t.Fatalf("publish with a failed write: %v", err)
	}
	if after, _ := os.ReadFile(bundlePath(site, "alpha")); !bytes.Equal(after, before) {
		t.Error("alpha was published although beta failed")
	}
	if got := siteFiles(t, site); len(got) != 1 {
		t.Errorf("site holds %v: a temporary file or beta was left behind", got)
	}
}
