package sign

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func keys(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "k.pem"), filepath.Join(dir, "k.pub.pem")
	if err := Keygen(priv, pub); err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// The header uses a fixed epoch so FuzzParse seeds stay reproducible
var hdr = Header{Serial: 1, Expires: time.Unix(0, 0).UTC().Add(90 * 24 * time.Hour)}

func mustSign(t *testing.T, priv ed25519.PrivateKey, name string, policy []byte, h Header) string {
	t.Helper()
	sig, err := Sign(priv, name, policy, h)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestSignVerify(t *testing.T) {
	privPath, pubPath := keys(t)
	priv, err := LoadPrivate(privPath)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := LoadPublic(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	policy := []byte("apiVersion: x\n")
	sig := mustSign(t, priv, "baseline", policy, hdr)
	if h, err := Verify(pub, "baseline", policy, []byte(sig)); err != nil || h != hdr {
		t.Fatalf("header %+v, err %v", h, err)
	}
	other := func(old, new string) string { return strings.Replace(sig, old, new, 1) }
	for name, tc := range map[string]struct {
		name   string
		policy []byte
		sig    string
	}{
		"edited policy":    {"baseline", []byte("apiVersion: y\n"), sig},
		"truncated":        {"baseline", policy[:5], sig},
		"other name":       {"strict", policy, sig},
		"higher serial":    {"baseline", policy, other("serial 1", "serial 2")},
		"later expiry":     {"baseline", policy, other("expires "+hdr.Expiry(), "expires "+hdr.Expires.Add(24*time.Hour).Format(TimeFormat))},
		"garbage":          {"baseline", policy, "not base64!"},
		"short signature":  {"baseline", policy, "AAAA"},
		"empty":            {"baseline", policy, ""},
		"huge":             {"baseline", policy, strings.Repeat("A", 1000)},
		"no trailing LF":   {"baseline", policy, strings.TrimSuffix(sig, "\n")},
		"CRLF":             {"baseline", policy, strings.ReplaceAll(sig, "\n", "\r\n")},
		"extra line":       {"baseline", policy, sig + "\n"},
		"unknown format":   {"baseline", policy, other("/v2", "/unsupported")},
		"leading zero":     {"baseline", policy, other("serial 1", "serial 01")},
		"plus sign":        {"baseline", policy, other("serial 1", "serial +1")},
		"zero serial":      {"baseline", policy, other("serial 1", "serial 0")},
		"serial too large": {"baseline", policy, other("serial 1", "serial 9223372036854775808")},
		"offset expiry":    {"baseline", policy, other(hdr.Expiry(), strings.TrimSuffix(hdr.Expiry(), "Z")+"+00:00")},
		"fractional":       {"baseline", policy, other(hdr.Expiry(), strings.TrimSuffix(hdr.Expiry(), "Z")+".0Z")},
		"lowercase z":      {"baseline", policy, other(hdr.Expiry(), strings.TrimSuffix(hdr.Expiry(), "Z")+"z")},
		"two spaces":       {"baseline", policy, other("serial ", "serial  ")},
		"reordered":        {"baseline", policy, strings.Join([]string{signatureTag, strings.Split(sig, "\n")[2], strings.Split(sig, "\n")[1], strings.Split(sig, "\n")[3], ""}, "\n")},
		"unpadded base64":  {"baseline", policy, other("==\n", "\n")},
		"expiry removed":   {"baseline", policy, other("expires "+hdr.Expiry(), "expires never")},
		"empty expiry":     {"baseline", policy, other("expires "+hdr.Expiry(), "expires ")},
	} {
		if _, err := Verify(pub, tc.name, tc.policy, []byte(tc.sig)); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	// Another key's signature doesn't verify
	otherPriv, _ := keys(t)
	op, _ := LoadPrivate(otherPriv)
	if _, err := Verify(pub, "baseline", policy, []byte(mustSign(t, op, "baseline", policy, hdr))); err == nil {
		t.Error("another key's signature verified")
	}
}

// A valid signature needs its format, serial and expiry headers
func TestBareSignatureRefused(t *testing.T) {
	privPath, pubPath := keys(t)
	priv, _ := LoadPrivate(privPath)
	pub, _ := LoadPublic(pubPath)
	policy := []byte("apiVersion: x\n")
	full := mustSign(t, priv, "baseline", policy, hdr)
	_, raw, err := Parse([]byte(full))
	if err != nil {
		t.Fatal(err)
	}
	bare := base64.StdEncoding.EncodeToString(raw) + "\n"
	if _, err := Verify(pub, "baseline", policy, []byte(bare)); !errors.Is(err, ErrBadSignature) {
		t.Errorf("bare signature: %v", err)
	}
	if _, err := Verify(pub, "baseline", policy, []byte("AAAA\n")); !errors.Is(err, ErrBadSignature) {
		t.Errorf("short base64: %v", err)
	}
}

func TestSignRefusesBadHeaders(t *testing.T) {
	privPath, _ := keys(t)
	priv, _ := LoadPrivate(privPath)
	for name, h := range map[string]Header{
		"zero serial":      {Serial: 0, Expires: hdr.Expires},
		"serial too large": {Serial: MaxSerial + 1, Expires: hdr.Expires},
		"fraction":         {Serial: 1, Expires: hdr.Expires.Add(time.Millisecond)},
		"year 10000":       {Serial: 1, Expires: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
	} {
		if _, err := Sign(priv, "baseline", nil, h); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
	// Any time zone is signed as UTC
	h := Header{Serial: 1, Expires: hdr.Expires.In(time.FixedZone("x", 3600))}
	if sig := mustSign(t, priv, "baseline", nil, h); !strings.Contains(sig, "\nexpires "+hdr.Expiry()+"\n") {
		t.Errorf("not UTC: %q", sig)
	}
}

func TestSignExpiryUTCYearBoundary(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	// The protocol's upper year boundary applies to UTC, regardless of the input zone
	end := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		expires time.Time
		valid   bool
	}{
		{"last UTC second", end.Add(-time.Second), true},
		{"UTC year 10000", end, false},
		{"local year 10000, UTC year 9999", end.Add(-time.Second).In(time.FixedZone("east", 3600)), true},
		{"local year 9999, UTC year 10000", end.In(time.FixedZone("west", -3600)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := Sign(priv, "baseline", nil, Header{Serial: 1, Expires: tc.expires})
			if !tc.valid {
				if err == nil {
					t.Fatal("signed an expiry beyond the UTC year limit")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			h, err := Verify(pub, "baseline", nil, []byte(sig))
			if err != nil {
				t.Fatal(err)
			}
			if h.Serial != 1 || !h.Expires.Equal(tc.expires) {
				t.Fatalf("verified header = %+v, want serial 1 and expiry %s", h, tc.expires.UTC())
			}
		})
	}
}

// A policy may be signed without expiry
func TestNoExpiry(t *testing.T) {
	privPath, pubPath := keys(t)
	priv, _ := LoadPrivate(privPath)
	pub, _ := LoadPublic(pubPath)
	policy := []byte("apiVersion: x\n")
	sig := mustSign(t, priv, "baseline", policy, Header{Serial: 5})
	if !strings.Contains(sig, "\nexpires never\n") {
		t.Fatalf("no expiry written as %q", sig)
	}
	h, err := Verify(pub, "baseline", policy, []byte(sig))
	if err != nil || h.Serial != 5 || !h.Expires.IsZero() || h.Expired(time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)) || h.Expiry() != "never" {
		t.Fatalf("header %+v, err %v", h, err)
	}
	for _, v := range []string{"expires " + hdr.Expiry(), "expires Never", "expires NEVER", "expires 0", "expires "} {
		if _, err := Verify(pub, "baseline", policy, []byte(strings.Replace(sig, "expires never", v, 1))); err == nil {
			t.Errorf("%q: verified", v)
		}
	}
}

func TestExpired(t *testing.T) {
	if hdr.Expired(hdr.Expires.Add(-time.Second)) || !hdr.Expired(hdr.Expires) || !hdr.Expired(hdr.Expires.Add(time.Hour)) {
		t.Error("expiry boundary")
	}
}

// Parse accepts exactly what Sign writes: anything it accepts is written back byte for byte
func FuzzParse(f *testing.F) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	sig, _ := Sign(priv, "baseline", nil, hdr)
	f.Add([]byte(sig))
	sig, _ = Sign(priv, "baseline", nil, Header{Serial: 1})
	f.Add([]byte(sig))
	f.Add([]byte("AAAA\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, raw, err := Parse(b)
		if err != nil {
			return
		}
		again := signatureTag + "\nserial " + strconv.FormatUint(h.Serial, 10) + "\nexpires " + h.Expiry() +
			"\nsignature " + base64.StdEncoding.EncodeToString(raw) + "\n"
		if again != string(b) {
			t.Fatalf("accepted a variant: %q", b)
		}
	})
}

// Keygen never replaces a key, the public one included: a new private key
// beside an old public key would leave a pair that doesn't match
// A refused Keygen leaves no file of its own behind
func TestKeygenNeverOverwrites(t *testing.T) {
	priv, pub := keys(t)
	before := map[string]string{}
	for _, p := range []string{priv, pub} {
		data, _ := os.ReadFile(p)
		before[p] = string(data)
	}
	dir := t.TempDir()
	for _, tc := range []struct{ name, priv, pub string }{
		{"private key exists", priv, filepath.Join(dir, "new.pub")},
		{"public key exists", filepath.Join(dir, "new.key"), pub},
		{"one path for both", filepath.Join(dir, "both"), filepath.Join(dir, "both")},
	} {
		if err := Keygen(tc.priv, tc.pub); !errors.Is(err, fs.ErrExist) {
			t.Errorf("%s: err = %v, want one that matches fs.ErrExist", tc.name, err)
		}
	}
	for p, data := range before {
		if after, _ := os.ReadFile(p); string(after) != data {
			t.Errorf("%s changed", p)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("a refused Keygen left %v", entries)
	}
	if fi, _ := os.Stat(priv); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("private key mode %v", fi.Mode().Perm())
	}
}

func TestLoadRejectsWrongKeys(t *testing.T) {
	priv, pub := keys(t)
	if _, err := LoadPublic(priv); err == nil {
		t.Error("a private key loaded as public")
	}
	if _, err := LoadPrivate(pub); err == nil {
		t.Error("a public key loaded as private")
	}
	junk := filepath.Join(t.TempDir(), "junk.pem")
	os.WriteFile(junk, []byte("hello"), 0o600)
	if _, err := LoadPublic(junk); err == nil {
		t.Error("junk loaded")
	}
}

// A public key of the wrong length is a bad signature, not a panic
func TestVerifyWrongKeyLength(t *testing.T) {
	privPath, _ := keys(t)
	priv, err := LoadPrivate(privPath)
	if err != nil {
		t.Fatal(err)
	}
	policy := []byte("apiVersion: x\n")
	sig := mustSign(t, priv, "baseline", policy, hdr)
	for _, pub := range []ed25519.PublicKey{nil, make(ed25519.PublicKey, 31), make(ed25519.PublicKey, 33)} {
		if _, err := Verify(pub, "baseline", policy, []byte(sig)); !errors.Is(err, ErrBadSignature) {
			t.Errorf("key of %d bytes: %v", len(pub), err)
		}
	}
}
