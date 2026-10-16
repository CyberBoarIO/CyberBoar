package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestApplyOpencode(t *testing.T) {
	dir := t.TempDir()
	proj := filepath.Join(dir, "proj")
	os.MkdirAll(filepath.Join(proj, ".cyberboar"), 0o755)
	policyPath := filepath.Join(proj, ".cyberboar", "policy.yaml")
	pol, err := os.ReadFile("../../examples/baseline.yaml")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(policyPath, pol, 0o644)
	outside := filepath.Join(dir, "policy.yaml")
	os.WriteFile(outside, pol, 0o644)

	run := func(a applyArgs, env map[string]string) (int, string, string) {
		var out bytes.Buffer
		var errs strings.Builder
		fail := func(format string, args ...any) int { fmt.Fprintf(&errs, format, args...); return 1 }
		usage := func(format string, args ...any) int { fmt.Fprintf(&errs, format, args...); return 2 }
		if a.deadline == 0 {
			a.deadline = 5 * time.Second
		}
		code := applyOpencode(a, &out, func(k string) string { return env[k] }, fail, usage)
		return code, out.String(), errs.String()
	}

	// User scope, under XDG_CONFIG_HOME when it is set
	xdg := filepath.Join(dir, "xdg")
	code, out, errs := run(applyArgs{policy: policyPath, scope: "user", dir: proj, command: "/bin/cb", write: true},
		map[string]string{"HOME": filepath.Join(dir, "home"), "XDG_CONFIG_HOME": xdg})
	target := filepath.Join(xdg, "opencode", "plugin", "cyberboar.js")
	if code != 0 || !strings.Contains(out, "wrote "+target) {
		t.Fatalf("user scope: %d %q %q", code, out, errs)
	}
	shim, _ := os.ReadFile(target)
	if !strings.Contains(string(shim), `const command = "/bin/cb";`) || !strings.Contains(string(shim), `"--policy","`+policyPath+`"`) ||
		!strings.Contains(string(shim), "const cwd = false ?") {
		t.Errorf("user scope plugin:\n%s", shim)
	}
	// Without XDG_CONFIG_HOME: ~/.config
	code, out, _ = run(applyArgs{policy: policyPath, scope: "user", dir: proj}, map[string]string{"HOME": filepath.Join(dir, "home")})
	if code != 0 || !strings.Contains(out, filepath.Join(dir, "home", ".config", "opencode", "plugin", "cyberboar.js")+" (dry run") {
		t.Errorf("user scope dry run: %d %q", code, out)
	}

	// Project scope: a relative policy, the hook on PATH, run in the project root
	code, out, errs = run(applyArgs{policy: policyPath, scope: "project", dir: proj, write: true}, nil)
	target = filepath.Join(proj, ".opencode", "plugin", "cyberboar.js")
	if code != 0 || !strings.Contains(out, "wrote "+target) {
		t.Fatalf("project scope: %d %q %q", code, out, errs)
	}
	shim, _ = os.ReadFile(target)
	if !strings.Contains(string(shim), `const command = "cyberboar";`) || !strings.Contains(string(shim), `"--policy",".cyberboar/policy.yaml"`) ||
		!strings.Contains(string(shim), "const cwd = true ?") {
		t.Errorf("project scope plugin:\n%s", shim)
	}

	// Flag values opencode doesn't take are usage errors (exit 2)
	missing := filepath.Join(dir, "none.yaml")
	for name, tc := range map[string]struct {
		a    applyArgs
		code int
		want string
	}{
		"policy outside the project": {applyArgs{policy: outside, scope: "project", dir: proj}, 1, "must be inside the project"},
		"managed":                    {applyArgs{policy: missing, scope: "managed", dir: proj}, 2, "--pure"},
		"lock":                       {applyArgs{policy: missing, scope: "user", dir: proj, lock: true}, 2, "--pure"},
		"unknown scope":              {applyArgs{policy: missing, scope: "local", dir: proj}, 2, "unknown --scope"},
		"deadline near the timeout":  {applyArgs{policy: missing, scope: "user", dir: proj, deadline: 14 * time.Second}, 2, "below the plugin's hook timeout"},
		"missing policy":             {applyArgs{policy: missing, scope: "user", dir: proj}, 1, "no such file"},
	} {
		code, _, errs := run(tc.a, map[string]string{"HOME": filepath.Join(dir, "home")})
		if code != tc.code || !strings.Contains(errs, tc.want) {
			t.Errorf("%s: %d %q, want exit %d and an error containing %q", name, code, errs, tc.code, tc.want)
		}
	}
}
