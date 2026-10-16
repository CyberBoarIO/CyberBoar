package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignReplacesSymlinkWithoutChangingTarget(t *testing.T) {
	c := newCLI(t)
	priv, pub := filepath.Join(c.home, "key"), filepath.Join(c.home, "key.pub")
	if code := c.run("", "keygen", "--private", priv, "--public", pub); code != 0 {
		t.Fatal(c.err.String())
	}
	pol := filepath.Join(c.home, "baseline.yaml")
	data, err := os.ReadFile(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pol, data, 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(c.home, "unrelated.txt")
	const original = "keep unrelated content\n"
	if err := os.WriteFile(target, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, pol+".sig"); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if code := c.run("", "sign", "--key", priv, "--serial", "1", "--expires", "720h", pol); code != 0 {
		t.Fatal(c.err.String())
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != original {
		t.Fatalf("sign changed the symlink target: %q, %v", got, err)
	}
	if info, err := os.Lstat(pol + ".sig"); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("signature is not a regular replacement: %v, %v", info, err)
	}
	if code := c.run("", "verify", "--pubkey", pub, pol); code != 0 {
		t.Fatal(c.err.String())
	}
}

// keygen refuses to replace an existing public key, and then writes no private key either
func TestKeygenKeepsPublicKey(t *testing.T) {
	c := newCLI(t)
	priv, pub := filepath.Join(c.home, "k"), filepath.Join(c.home, "k.pub")
	os.WriteFile(pub, []byte("the key endpoints have\n"), 0o644)
	if code := c.run("", "keygen", "-private", priv, "-public", pub); code != 1 {
		t.Errorf("exit %d, want 1 (%s)", code, c.err.String())
	}
	if got, _ := os.ReadFile(pub); string(got) != "the key endpoints have\n" {
		t.Errorf("the public key was replaced: %q", got)
	}
	if _, err := os.Stat(priv); err == nil {
		t.Error("wrote a private key that doesn't match the public key")
	}
}

// sign takes a serial and an expiry, refuses anything vague about them, and
// won't write a signature endpoints that have the old one would refuse
func TestSignSerialExpiry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct {
		name string
		now  time.Time
	}{
		{"present", now},
		{"past", now.AddDate(-50, 0, 0)},
		{"future", now.AddDate(50, 0, 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testSignSerialExpiryAt(t, tc.now)
		})
	}
}

func testSignSerialExpiryAt(t *testing.T, now time.Time) {
	t.Helper()
	c := newCLI(t)
	c.now = fixedClock(now)
	priv, pub := filepath.Join(c.home, "k"), filepath.Join(c.home, "k.pub")
	if code := c.run("", "keygen", "-private", priv, "-public", pub); code != 0 {
		t.Fatal(c.err.String())
	}
	pol := filepath.Join(c.home, "baseline.yaml")
	data, _ := os.ReadFile(baseline)
	os.WriteFile(pol, data, 0o644)
	signArgs := func(serial, expires string) []string {
		return []string{"sign", "-key", priv, "-serial", serial, "-expires", expires, pol}
	}
	for _, args := range [][]string{
		{"sign", "-key", priv, pol},
		{"sign", "-key", priv, "-serial", "1", pol},
		{"sign", "-key", priv, "-expires", "720h", pol},
	} {
		if code := c.run("", args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	for _, a := range [][2]string{
		{"0", "720h"}, {"01", "720h"}, {"0x10", "720h"}, {"+1", "720h"}, {"9223372036854775808", "720h"}, {"-1", "720h"},
		{"1", "-1h"}, {"1", "0s"}, {"1", now.Format(time.RFC3339)}, {"1", "8785h"},
		{"1", now.Add(367 * 24 * time.Hour).Format(time.RFC3339)},
		{"1", now.Add(24*time.Hour + 500*time.Millisecond).Format(time.RFC3339Nano)},
		{"1", "90d"}, {"1", now.Add(24 * time.Hour).Format(time.DateOnly)}, {"1", "-1"}, {"1", "Never"}, {"1", "00"},
	} {
		if code := c.run("", signArgs(a[0], a[1])...); code != 1 {
			t.Errorf("-serial %s -expires %s: exit %d, want 1", a[0], a[1], code)
		}
	}
	if _, err := os.Stat(pol + ".sig"); !os.IsNotExist(err) {
		t.Fatal("a refused sign wrote a signature")
	}

	expires := now.Add(90 * 24 * time.Hour).Format(time.RFC3339)
	if code := c.run("", signArgs("10", "2160h")...); code != 0 || !strings.Contains(c.out.String(), "serial 10, expires "+expires) {
		t.Fatalf("exit %d: %s%s", code, c.out.String(), c.err.String())
	}
	if code := c.run("", "verify", "-pubkey", pub, pol); code != 0 || !strings.Contains(c.out.String(), "ok      "+pol+" (serial 10, expires "+expires+")") {
		t.Fatalf("verify: exit %d: %s", code, c.out.String())
	}
	// The same signature again is fine (CI re-runs)
	// The same serial with another expiry, or a lower one is not fine
	if code := c.run("", signArgs("10", expires)...); code != 0 {
		t.Errorf("same signature again: exit %d: %s", code, c.err.String())
	}
	before, _ := os.ReadFile(pol + ".sig")
	for _, a := range [][2]string{{"10", "2161h"}, {"9", "2160h"}} {
		if code := c.run("", signArgs(a[0], a[1])...); code != 1 || !strings.Contains(c.err.String(), "already signed with serial 10") {
			t.Errorf("-serial %s -expires %s: exit %d: %s", a[0], a[1], code, c.err.String())
		}
	}
	if after, _ := os.ReadFile(pol + ".sig"); string(after) != string(before) {
		t.Error("a refused sign replaced the signature")
	}
	// 0 or never: no expiry, with a warning on every run
	for i, e := range []string{"0", "never"} {
		if code := c.run("", signArgs(fmt.Sprint(20+i), e)...); code != 0 || !strings.Contains(c.out.String(), "expires never") || !strings.Contains(c.err.String(), "WARNING: no expiry") {
			t.Fatalf("-expires %s: exit %d: %s%s", e, code, c.out.String(), c.err.String())
		}
	}
	c.now = fixedClock(now.AddDate(50, 0, 0))
	if code := c.run("", "verify", "-pubkey", pub, pol); code != 0 || !strings.Contains(c.out.String(), "(serial 21, expires never)") {
		t.Fatalf("verify of a policy without expiry: exit %d: %s", code, c.out.String())
	}
	c.now = fixedClock(now)
	// Any offset is written as UTC
	offsetExpiry := now.Add(60 * 24 * time.Hour).In(time.FixedZone("UTC+1", 3600))
	if code := c.run("", signArgs("31", offsetExpiry.Format(time.RFC3339))...); code != 0 || !strings.Contains(c.out.String(), "expires "+offsetExpiry.UTC().Format(time.RFC3339)) {
		t.Fatalf("exit %d: %s%s", code, c.out.String(), c.err.String())
	}
	c.now = fixedClock(now.Add(61 * 24 * time.Hour))
	if code := c.run("", "verify", "-pubkey", pub, pol); code != 1 || !strings.Contains(c.out.String(), "expired "+pol) {
		t.Errorf("verify of an expired policy: exit %d: %s", code, c.out.String())
	}
}
