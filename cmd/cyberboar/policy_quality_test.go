package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPolicyRegressionCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fixture paths: Windows adapter behavior is tested separately")
	}
	cases := "../../testdata/policy-cases/baseline.tests.yaml"
	if code, out, err := call(t, "", "test", "--policy", baseline, "--cases", cases); code != 0 || !strings.Contains(out, "3 passed, 0 failed") {
		t.Fatalf("test: exit %d out %q err %q", code, out, err)
	}
	tmp := filepath.Join(t.TempDir(), "cases.yaml")
	good, err := os.ReadFile(cases)
	if err != nil {
		t.Fatal(err)
	}
	// An expectation mismatch is a failure, not a usage error
	bad := strings.Replace(string(good), "expect: deny", "expect: allow", 1)
	if err := os.WriteFile(tmp, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := call(t, "", "test", "--policy", baseline, "--cases", tmp); code != 1 || !strings.Contains(out, "FAIL Block env file") {
		t.Fatalf("mismatch: exit %d %q", code, out)
	}
	// Validation happens before execution: no partial success for malformed inputs
	for _, src := range []string{
		"tests: []\n",
		"tests:\n  - name: x\n    action: {mcp: bad}\n    expect: deny\n",
		"tests:\n  - name: x\n    action: {read: a, write: b}\n    expect: allow\n",
		"tests:\n  - name: x\n    action: {command: ls}\n    expect: maybe\n",
		"tests:\n  - name: x\n    action: {command: ls}\n    expect: allow\n    unexpected: true\n",
		"tests:\n  - name: x\n    action: {command: ls, shell: fish}\n    expect: allow\n",
		"tests:\n  - name: x\n    action: {read: a, shell: powershell}\n    expect: allow\n",
	} {
		if err := os.WriteFile(tmp, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		if code, out, _ := call(t, "", "test", "--policy", baseline, "--cases", tmp); code != 1 || strings.Contains(out, "PASS ") {
			t.Errorf("invalid %q: exit %d %q", src, code, out)
		}
	}
	// A PowerShell case is read as PowerShell: cat is Get-Content
	ps := "tests:\n  - name: ps\n    action: {command: 'cat .env', shell: powershell, cwd: /work/repo, home: /home/dev, workspace: /work/repo}\n    expect: deny\n"
	if err := os.WriteFile(tmp, []byte(ps), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := call(t, "", "test", "--policy", baseline, "--cases", tmp); code != 0 || !strings.Contains(out, "PASS ps") {
		t.Errorf("PowerShell case: exit %d %q", code, out)
	}
	if code, _, _ := call(t, "", "test"); code != 2 {
		t.Errorf("missing flags: exit %d", code)
	}
}
