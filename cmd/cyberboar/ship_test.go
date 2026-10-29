package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/internal/endpoint/ship"
	"cyberboar.dev/cyberboar/internal/protocoltest"
	"cyberboar.dev/cyberboar/pkg/audit"
	"cyberboar.dev/cyberboar/pkg/sign"
)

// cli runs the command line with HOME in a temporary directory, the extra
// environment given, and the clock now.
type cli struct {
	t        *testing.T
	home     string
	env      map[string]string
	now      func() time.Time
	out, err bytes.Buffer
}

func newCLI(t *testing.T) *cli {
	return &cli{t: t, home: t.TempDir(), env: map[string]string{}, now: time.Now}
}

func (c *cli) run(stdin string, args ...string) int {
	c.t.Helper()
	c.out.Reset()
	c.err.Reset()
	env := func(k string) string {
		if k == "HOME" {
			return c.home
		}
		return c.env[k]
	}
	return runAt(c.now, args, strings.NewReader(stdin), &c.out, &c.err, env)
}

// enroll enrolls the CLI's machine with console.
func (c *cli) enroll(console *protocoltest.Console, policy string) {
	c.t.Helper()
	c.env[envName("enroll-token")] = console.Token(policy, 1)
	defer delete(c.env, envName("enroll-token"))
	if code := c.run("", "enroll", "-server", console.URL, "-ca", console.CAFile(c.t)); code != 0 {
		c.t.Fatalf("enroll exit %d: %s", code, c.err.String())
	}
}

// The hook's audit log reaches a console: hook -> file -> ship -> server.
func TestHookAuditShipsToConsole(t *testing.T) {
	console := protocoltest.New(t, "", nil)
	c := newCLI(t)
	c.enroll(console, "baseline")
	auditLog := filepath.Join(c.home, "audit.jsonl")
	if code, _, _ := call(t, catEnv, "hook", "--policy", baseline, "--audit", auditLog); code != 2 {
		t.Fatalf("hook exit %d", code)
	}
	if code := c.run("", "ship", "-audit", auditLog, "-ca", console.CAFile(t)); code != 0 {
		t.Fatalf("ship exit %d: %s", code, c.err.String())
	}
	batches := console.Batches()
	if len(batches) != 1 || len(batches[0].Events) != 1 {
		t.Fatalf("console got %d batches", len(batches))
	}
	ev, err := audit.ParseLine(batches[0].Events[0])
	if err != nil || ev.Decision != "deny" || len(ev.Actions) != 1 || ev.Actions[0].Command != "cat .env" || ev.PolicyName != "baseline" {
		t.Fatalf("console got %+v (%v)", ev, err)
	}
	if _, err := os.Stat(filepath.Join(c.home, ".local", "state", "cyberboar", "endpoint-id")); err != nil {
		t.Errorf("endpoint ID not in the XDG default state dir: %v", err)
	}
	// A sink, given or from the policy, must be the enrolled console's
	// The policy is checked even when --sink is given too
	events := console.URL + "/api/v1/events"
	ownPolicy := filepath.Join(c.home, "policy.yaml")
	pol, err := os.ReadFile(baseline)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(ownPolicy, bytes.Replace(pol, []byte("https://cyberboar.internal/api/v1/events"), []byte(events), 1), 0o600)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-sink", "https://elsewhere.example/api/v1/events"}, "enrolled with"},
		{[]string{"-policy", baseline}, "enrolled with"}, // spec.audit.sink is another host
		{[]string{"-sink", events, "-policy", baseline}, "enrolled with"},
		{[]string{"-sink", events, "-policy", filepath.Join(c.home, "none.yaml")}, "no such file"},
		{[]string{"-sink", "https://elsewhere.example/api/v1/events", "-policy", ownPolicy}, "enrolled with"},
	} {
		if code := c.run("", append([]string{"ship", "-audit", auditLog, "-ca", console.CAFile(t)}, tc.args...)...); code != 1 ||
			!strings.Contains(c.err.String(), tc.want) {
			t.Errorf("%v: exit %d: %s", tc.args, code, c.err.String())
		}
	}
	if n := len(console.Batches()); n != 1 {
		t.Errorf("shipped with a sink that isn't the console's: %d batches", n)
	}
	for _, args := range [][]string{{"-sink", events}, {"-policy", ownPolicy}, {"-sink", events, "-policy", ownPolicy}} {
		if code := c.run("", append([]string{"ship", "-audit", auditLog, "-ca", console.CAFile(t)}, args...)...); code != 0 {
			t.Errorf("the console's own sink %v: exit %d: %s", args, code, c.err.String())
		}
	}
	// A revoked endpoint ships nothing, and keeps its events
	appendLine(t, auditLog)
	console.Revoke(console.Endpoints()[0].ID)
	if code := c.run("", "ship", "-audit", auditLog, "-ca", console.CAFile(t)); code != 1 || !strings.Contains(c.err.String(), "revoked") {
		t.Errorf("revoked: exit %d: %s", code, c.err.String())
	}
	if n := len(console.Batches()); n != 4 {
		t.Errorf("the console has %d batches", n)
	}
}

// ship warns when the audit log was rotated since its last run, since lines
// the old log got after that run were never sent.
func TestShipWarnsAboutRotation(t *testing.T) {
	console := protocoltest.New(t, "", nil)
	c := newCLI(t)
	c.enroll(console, "baseline")
	auditLog := filepath.Join(c.home, "audit.jsonl")
	os.WriteFile(auditLog, nil, 0o600)
	appendLine(t, auditLog)
	ship := func() string {
		t.Helper()
		if code := c.run("", "ship", "-audit", auditLog, "-ca", console.CAFile(t)); code != 0 {
			t.Fatalf("ship exit %d: %s", code, c.err.String())
		}
		return c.err.String()
	}
	if errs := ship(); strings.Contains(errs, "rotate") {
		t.Errorf("first run: %q", errs)
	}
	appendLine(t, auditLog)
	if err := os.Rename(auditLog, auditLog+".1"); err != nil {
		t.Fatal(err)
	}
	// Every line the hook writes starts with its own timestamp
	os.WriteFile(auditLog, []byte(fmt.Sprintf(`{"time":%q,"agent":"claude-code","decision":"deny","rule":"r","reason":"x","durationMs":1}`+"\n", time.Now().UTC().Format(time.RFC3339Nano))), 0o600)
	if errs := ship(); !strings.Contains(errs, "truncated or replaced") || !strings.Contains(errs, "right after a ship run") {
		t.Errorf("no warning after a rotation: %q", errs)
	}
	if errs := ship(); strings.Contains(errs, "rotate") {
		t.Errorf("warned twice for one rotation: %q", errs)
	}
}

// appendLine adds one more audit event to path.
func appendLine(t *testing.T, path string) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(f, `{"time":%q,"agent":"claude-code","decision":"deny","rule":"r","reason":"x","durationMs":1}`+"\n", time.Now().UTC().Format(time.RFC3339Nano))
	f.Close()
}

func TestShipArguments(t *testing.T) {
	dir := t.TempDir()
	env := func(k string) string { return map[string]string{"HOME": dir}[k] }
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"ship"}, 2}, // no audit log
		{[]string{"ship", "-audit", "a.jsonl", "-every", "10ms"}, 2},         // too often
		{[]string{"ship", "-audit", "a.jsonl", "-insecure-http"}, 2},         // the flag is gone
		{[]string{"ship", "-audit", "a.jsonl"}, 1},                           // not enrolled
		{[]string{"ship", "-audit", "a.jsonl", "-sink", "https://x/api"}, 1}, // not enrolled
	} {
		var errb bytes.Buffer
		if code := run(tc.args, strings.NewReader(""), &bytes.Buffer{}, &errb, env); code != tc.code {
			t.Errorf("%v: exit %d, want %d (%s)", tc.args, code, tc.code, errb.String())
		}
	}
}

func TestDefaultStateDir(t *testing.T) {
	for _, tc := range []struct{ xdg, home, want string }{
		{"/x/state", "/home/dev", "/x/state/cyberboar"},
		{"relative", "/home/dev", "/home/dev/.local/state/cyberboar"},
		{"", "/home/dev", "/home/dev/.local/state/cyberboar"},
		{"", "", ""},
	} {
		h := host{goos: "linux", getenv: func(k string) string { return map[string]string{"XDG_STATE_HOME": tc.xdg, "HOME": tc.home}[k] }}
		got, err := h.defaultStateDir()
		if got != tc.want || (err != nil) != (tc.want == "") {
			t.Errorf("%+v: %q, %v", tc, got, err)
		}
	}
}

// keygen -> sign -> console -> enroll -> pull -> hook with the pinned key.
func TestSignedPolicyEndToEnd(t *testing.T) {
	c := newCLI(t)
	dir := c.home
	priv, pub := filepath.Join(dir, "k"), filepath.Join(dir, "k.pub")
	if code := c.run("", "keygen", "-private", priv, "-public", pub); code != 0 {
		t.Fatal(c.err.String())
	}
	pols := filepath.Join(dir, "policies")
	os.MkdirAll(pols, 0o755)
	data, _ := os.ReadFile(baseline)
	os.WriteFile(filepath.Join(pols, "baseline.yaml"), data, 0o644)
	if code := c.run("", "sign", "-key", priv, "-serial", "1", "-expires", "720h", filepath.Join(pols, "baseline.yaml")); code != 0 {
		t.Fatal(c.err.String())
	}
	if code := c.run("", "verify", "-pubkey", pub, filepath.Join(pols, "baseline.yaml")); code != 0 {
		t.Fatal(c.out.String())
	}
	k, _ := sign.LoadPublic(pub)
	console := protocoltest.New(t, pols, k)
	installed := filepath.Join(dir, "installed", "policy.yaml")
	ca := console.CAFile(t)
	if code := c.run("", "pull", "-server", console.URL, "-name", "baseline", "-out", installed, "-pubkey", pub, "-ca", ca); code != 1 ||
		!strings.Contains(c.err.String(), "not enrolled") && !strings.Contains(c.err.String(), "401") {
		t.Fatalf("pulled from a console without enrolling: exit %d: %s", code, c.err.String())
	}
	c.enroll(console, "baseline")
	// The enrollment says where and what: no --server or --name.
	if code := c.run("", "pull", "-out", installed, "-pubkey", pub, "-ca", ca); code != 0 {
		t.Fatal(c.err.String())
	}
	for _, args := range [][]string{{"-name", "other"}, {"-server", "https://elsewhere.example"}} {
		if code := c.run("", append([]string{"pull", "-out", installed, "-pubkey", pub, "-ca", ca}, args...)...); code != 1 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
	if code, o, _ := call(t, catEnv, "hook", "--policy", installed, "--pubkey", pub); code != 2 || !strings.Contains(o, "files.deny") && !strings.Contains(o, ".env") {
		t.Fatalf("signed policy in force: exit %d %s", code, o)
	}
	if code, o, _ := call(t, lsSrc, "hook", "--policy", installed, "--pubkey", pub); code != 0 || o != "" {
		t.Fatalf("harmless call: exit %d %s", code, o)
	}
	// Once it expires, so does a policy nobody signs again.
	if code, o, _ := callAt(t, fixedClock(time.Now().Add(721*time.Hour)), lsSrc, "hook", "--policy", installed, "--pubkey", pub); code != 2 || !strings.Contains(o, "expired") {
		t.Fatalf("expired policy: exit %d %s", code, o)
	}
	// Tampering with the installed policy blocks everything.
	os.WriteFile(installed, append(data, "# weakened\n"...), 0o644)
	if code, o, _ := call(t, lsSrc, "hook", "--policy", installed, "--pubkey", pub); code != 2 || !strings.Contains(o, "signature") {
		t.Fatalf("tampered policy: exit %d %s", code, o)
	}
	// A policy the console didn't assign this endpoint isn't served to it.
	console.Assign(console.Endpoints()[0].ID, "permissive")
	if code := c.run("", "pull", "-out", installed, "-pubkey", pub, "-ca", ca, "-name", "baseline"); code != 1 {
		t.Errorf("pulled a policy that is no longer assigned: exit %d", code)
	}
}

// --insecure-skip-verify talks TLS without checking the certificate.
// Enrolling that way needs the console's key, since nothing else would authenticate the console.
func TestShipSkipVerify(t *testing.T) {
	console := protocoltest.New(t, "", nil)
	c := newCLI(t)
	c.env[envName("insecure-skip-verify")] = "1"
	c.env[envName("enroll-token")] = console.Token("baseline", 1)
	if code := c.run("", "enroll", "-server", console.URL); code != 1 {
		t.Fatalf("an environment variable turned verification off: exit %d", code)
	}
	if code := c.run("", "enroll", "-server", console.URL, "-insecure-skip-verify"); code != 1 || !strings.Contains(c.err.String(), "-console-key") {
		t.Fatalf("enrolled with neither a verified server nor a pinned key: exit %d: %s", code, c.err.String())
	}
	if code := c.run("", "enroll", "-server", console.URL, "-insecure-skip-verify", "-console-key", console.ConsoleKeyFile(t)); code != 0 {
		t.Fatalf("enroll exit %d: %s", code, c.err.String())
	}
	auditLog := filepath.Join(c.home, "audit.jsonl")
	if code, _, _ := call(t, catEnv, "hook", "--policy", baseline, "--audit", auditLog); code != 2 {
		t.Fatalf("hook exit %d", code)
	}
	if code := c.run("", "ship", "-audit", auditLog); code != 1 {
		t.Fatalf("an environment variable turned verification off: exit %d", code)
	}
	if code := c.run("", "ship", "-audit", auditLog, "-insecure-skip-verify"); code != 0 {
		t.Fatalf("exit %d: %s", code, c.err.String())
	}
	if !strings.Contains(c.err.String(), "WARNING") || len(console.Batches()) != 1 {
		t.Fatalf("no warning or nothing shipped: %q, %d batches", c.err.String(), len(console.Batches()))
	}
}

func TestNextShipHonorsRetryAfter(t *testing.T) {
	srv := overloadedConsole(t)
	_, err := ship.Once(context.Background(), ship.Options{AuditPath: filepath.Join(t.TempDir(), "a.jsonl"), Sink: srv.URL + "/api/v1/events",
		StateDir: t.TempDir(), Version: "v", Client: srv.Client()})
	if got := nextShip(time.Second, err); got != 90*time.Second {
		t.Errorf("after a Retry-After of 90s: wait %s", got)
	}
	if got := nextShip(5*time.Minute, err); got != 5*time.Minute {
		t.Errorf("an interval longer than Retry-After: wait %s", got)
	}
	if got := nextShip(time.Second, nil); got != time.Second {
		t.Errorf("after success: wait %s", got)
	}
}

// overloadedConsole answers every batch with 503 and Retry-After: 90.
func overloadedConsole(t *testing.T) *httptest.Server {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "90")
		http.Error(w, "busy", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	return srv
}
