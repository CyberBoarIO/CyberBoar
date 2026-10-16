package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/internal/protocoltest"
)

func TestEnrollCommand(t *testing.T) {
	console := protocoltest.New(t, "", nil)
	console.SetCertValidity(time.Minute) // renewal is due at once
	ca := console.CAFile(t)
	c := newCLI(t)
	if code := c.run("", "enroll", "-server", console.URL, "-ca", ca); code != 1 || !strings.Contains(c.err.String(), "no enrollment token") {
		t.Fatalf("no token: exit %d: %s", code, c.err.String())
	}
	if code := c.run("", "enroll", "-server", console.URL, "-ca", ca, "-token", console.Token("baseline", 1)); code != 2 {
		t.Fatalf("a token as a flag value: exit %d", code)
	}
	if code := c.run("", "enroll", "-server", console.URL, "-ca", ca, "-key-storage", "keychain"); code != 2 ||
		!strings.Contains(c.err.String(), "not a key storage") {
		t.Fatalf("an unknown key storage: exit %d: %s", code, c.err.String())
	}
	big := filepath.Join(c.home, "big")
	os.WriteFile(big, []byte(strings.Repeat("x", maxTokenFile+1)), 0o600)
	if code := c.run("", "enroll", "-server", console.URL, "-ca", ca, "-token-file", big); code != 1 {
		t.Fatalf("an oversized token file: exit %d", code)
	}
	if code := c.run(console.Token("baseline", 1)+"\n", "enroll", "-server", console.URL+"/", "-ca", ca, "-token-file", "-"); code != 0 ||
		!strings.HasPrefix(c.out.String(), "enrolled: endpoint ") || !strings.Contains(c.out.String(), "policy baseline") || !strings.Contains(c.out.String(), "; key in ") {
		t.Fatalf("token on stdin: exit %d: %s%s", code, c.out.String(), c.err.String())
	}
	if code := c.run("", "enroll", "-server", console.URL, "-ca", ca); code != 0 || !strings.HasPrefix(c.out.String(), "already enrolled, certificate renewed") {
		t.Fatalf("again: exit %d: %s%s", code, c.out.String(), c.err.String())
	}
	other := protocoltest.New(t, "", nil)
	tokenFile := filepath.Join(c.home, "token")
	os.WriteFile(tokenFile, []byte(other.Token("baseline", 1)), 0o600)
	if code := c.run("", "enroll", "-server", other.URL, "-ca", other.CAFile(t), "-token-file", tokenFile); code != 1 ||
		!strings.Contains(c.err.String(), "enrolled with "+console.URL) {
		t.Fatalf("another console: exit %d: %s", code, c.err.String())
	}
	if code := c.run("", "enroll", "-server", console.URL, "-ca", ca, "-console-key", other.ConsoleKeyFile(t)); code != 1 {
		t.Fatalf("another pinned key: exit %d", code)
	}
	if code := c.run("", "enroll", "-server", console.URL, "-ca", ca, "-console-key", tokenFile); code != 1 {
		t.Fatalf("a console key that isn't one: exit %d", code)
	}
	// A renewal the console refuses fails enroll, which MDMs report
	console.Revoke(console.Endpoints()[0].ID)
	if code := c.run("", "enroll", "-server", console.URL, "-ca", ca); code != 1 || strings.Contains(c.out.String(), "renewed") ||
		!strings.Contains(c.err.String(), "revoked") {
		t.Fatalf("revoked: exit %d: %s%s", code, c.out.String(), c.err.String())
	}
}
