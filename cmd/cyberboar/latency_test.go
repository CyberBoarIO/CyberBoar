package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var latency = flag.Bool("latency", false, "run TestLatencyBudget (scripts/quality-checks.sh does, on its own)")

// Budget is the latency budget of docs/latency.md: the median wall time of
// one hook process, start to exit, for an everyday tool call
const budget = 50 * time.Millisecond

// latencyRuns is how many times each call runs; the median is checked, so
// one slow run on a busy machine doesn't fail CI
const latencyRuns = 15

// TestLatencyBudget runs the real binary as an agent does, with a signed
// policy, an audit log and a state directory, and holds every everyday call
// to the budget (docs/latency.md)
// It only runs with -latency: alone, so parallel packages don't skew the timing
func TestLatencyBudget(t *testing.T) {
	if !*latency {
		t.Skip("run with -args -latency (scripts/quality-checks.sh does)")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "cyberboar")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	policy := filepath.Join(dir, "policy.yaml")
	data, err := os.ReadFile(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy, data, 0o600); err != nil {
		t.Fatal(err)
	}
	key, pub := filepath.Join(dir, "k"), filepath.Join(dir, "k.pub")
	for _, args := range [][]string{
		{"keygen", "-private", key, "-public", pub},
		{"sign", "-key", key, "-serial", "1", "-expires", "720h", policy},
	} {
		if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", args[0], err, out)
		}
	}

	// A small project: 200 source files of 2 000 lines, as a grep -r walks.
	ws := filepath.Join(dir, "ws")
	lines := strings.Repeat("func f() { return }\n", 2000)
	for i := range 200 {
		p := filepath.Join(ws, fmt.Sprintf("pkg%d", i/20), fmt.Sprintf("f%d.go", i))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(lines), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(ws, "pkg0", "f0.go")
	write := strings.Repeat("package x\n\nfunc g() int { return 42 }\n", 200)

	for _, tc := range []struct{ name, tool, input string }{
		{"read a file", "Read", fmt.Sprintf(`{"file_path":%q}`, file)},
		{"simple command", "Bash", `{"command":"go test ./..."}`},
		{"pipeline", "Bash", `{"command":"cd pkg1 && grep -n return *.go | sort | head -20"}`},
		{"recursive grep", "Bash", `{"command":"grep -rn TODO ."}`},
		{"write a file", "Write", fmt.Sprintf(`{"file_path":%q,"content":%q}`, filepath.Join(ws, "new.go"), write)},
		{"edit a file", "Edit", fmt.Sprintf(`{"file_path":%q,"old_string":"func f() { return }\nfunc f() { return }\n","new_string":"func g() {}\n","replace_all":true}`, file)},
	} {
		in := fmt.Sprintf(`{"hook_event_name":"PreToolUse","session_id":"s","tool_use_id":"t","tool_name":%q,"cwd":%q,"tool_input":%s}`, tc.tool, ws, tc.input)
		var took []time.Duration
		for range latencyRuns {
			cmd := exec.Command(bin, "hook", "-policy", policy, "-pubkey", pub,
				"-audit", filepath.Join(dir, "audit.jsonl"), "-state", filepath.Join(dir, "state"))
			cmd.Stdin = strings.NewReader(in)
			cmd.Env = []string{"CLAUDE_PROJECT_DIR=" + ws, "HOME=" + dir}
			start := time.Now()
			out, err := cmd.CombinedOutput()
			took = append(took, time.Since(start))
			if err != nil {
				// Every call here is allowed: a deny would be a broken set-up, not a fast answer
				t.Fatalf("%s: %v\n%s", tc.name, err, out)
			}
		}
		slices.Sort(took)
		median := took[len(took)/2]
		t.Logf("%-15s median %v, max %v", tc.name, median.Round(100*time.Microsecond), took[len(took)-1].Round(100*time.Microsecond))
		if median > budget {
			t.Errorf("%s: median %v, over the %v budget (docs/latency.md)", tc.name, median, budget)
		}
	}
}
