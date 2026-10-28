package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/pkg/brand"
)

const baseline = "../../examples/baseline.yaml"

// The advanced baseline enables the session tripwire
const advancedBaseline = "../../examples/advanced-baseline.yaml"

func testEnv(k string) string {
	return map[string]string{"CLAUDE_PROJECT_DIR": "/work/repo", "HOME": "/home/dev"}[k]
}

func call(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	return callAt(t, time.Now, stdin, args...)
}

// callAt is call with the clock the commands read given by now
func callAt(t *testing.T, now func() time.Time, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	state := t.TempDir() // each call is a fresh tripwire state
	env := func(k string) string {
		if k == "XDG_STATE_HOME" {
			return state
		}
		return testEnv(k)
	}
	code = runAt(now, args, strings.NewReader(stdin), &out, &errb, env)
	return code, out.String(), errb.String()
}

const catEnv = `{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/work/repo","tool_input":{"command":"cat .env"}}`
const lsSrc = `{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/work/repo","tool_input":{"command":"ls src"}}`

func TestHookDeniesAndStaysSilent(t *testing.T) {
	if code, out, errs := call(t, catEnv, "hook", "--policy", baseline); code != 2 || !strings.Contains(out, `"deny"`) || errs == "" {
		t.Errorf("deny: exit %d stdout %q stderr %q", code, out, errs)
	}
	if code, out, errs := call(t, lsSrc, "hook", "--policy", baseline); code != 0 || out != "" || errs != "" {
		t.Errorf("no answer: exit %d stdout %q stderr %q", code, out, errs)
	}
}

// Misconfiguration must deny with exit 2: any other exit code lets the call run
func TestHookMisconfigurationDenies(t *testing.T) {
	for _, args := range [][]string{
		{"hook", "--no-such-flag"},
		{"hook", "--deadline", "soon", "--policy", baseline},
		{"hook", "--agent", "windsurf", "--policy", baseline},
		{"hook", "--policy", baseline, "extra"},
		{"hook"}, // no policy
		{"hook", "--policy", "/nonexistent/policy.yaml"},
		{"hook", "--policy", baseline, "--audit", "audit.jsonl"}, // relative: would follow the agent's cwd
	} {
		code, out, _ := call(t, lsSrc, args...)
		if code != 2 || !strings.Contains(out, `"permissionDecision":"deny"`) {
			t.Errorf("%v: want deny with exit 2, got exit %d stdout %q", args, code, out)
		}
		// Codex gets the deny as JSON with exit 0, which survives PowerShell
		codexArgs := append([]string{"hook", "--agent", "codex"}, args[1:]...)
		if slices.Contains(args, "--agent") {
			continue // the last --agent counts
		}
		if code, out, _ := call(t, lsSrc, codexArgs...); code != 0 || !strings.Contains(out, `"permissionDecision":"deny"`) {
			t.Errorf("%v: want deny with exit 0, got exit %d stdout %q", codexArgs, code, out)
		}
	}
	// A signing key that can't be read denies for every agent, before the input is read
	missing := filepath.Join(t.TempDir(), "nonexistent.pub")
	for agent := range agents {
		code, out, errs := call(t, lsSrc, "hook", "--agent", agent, "--policy", baseline, "--pubkey", missing)
		if agent == "codex" {
			code, errs = code+2, out
		}
		if code != 2 || !strings.Contains(out, `"permissionDecision":"deny"`) || !strings.Contains(errs, "signing key can't be read") {
			t.Errorf("%s with a missing key: exit %d stdout %q stderr %q", agent, code, out, errs)
		}
	}
}

func TestAgentArg(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--agent", "codex"}, "codex"},
		{[]string{"-agent=codex"}, "codex"},
		{[]string{"--policy", "p.yaml", "--agent", "codex", "--deadline", "5s"}, "codex"},
		{[]string{"--agent", "codex", "--agent", "cursor"}, "cursor"},
		{[]string{"--policy", "--agent", "codex"}, ""}, // --agent is the policy's value
		{[]string{"--no-such-flag", "x", "--agent", "codex"}, "codex"},
		{[]string{"extra", "--agent", "codex"}, ""},
		{[]string{"--", "--agent", "codex"}, ""},
		{[]string{"--agent"}, ""},
		{nil, ""},
	} {
		if got := agentArg(c.args); got != c.want {
			t.Errorf("agentArg(%q) = %q, want %q", c.args, got, c.want)
		}
	}
}

// panicWriter is an output whose every write panics
type panicWriter struct{}

func (panicWriter) Write([]byte) (int, error) { panic("write to a closed pipe") }

// When writing the answer panics, the deny goes to stderr alone, with exit 2
// Writing it to the same output again would panic once more
func TestHookAnswerWritePanics(t *testing.T) {
	for _, input := range []string{catEnv, lsSrc} {
		var errb bytes.Buffer
		code := func() (code int) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("a panic escaped the hook: %v", r)
				}
			}()
			return run([]string{"hook", "--policy", baseline}, strings.NewReader(input), panicWriter{}, &errb, testEnv)
		}()
		if code != 2 || !strings.Contains(errb.String(), "internal error in the hook") {
			t.Errorf("exit %d, stderr %q; want exit 2 and the reason", code, errb.String())
		}
	}
	code := func() (code int) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("a panic escaped the hook: %v", r)
			}
		}()
		return run([]string{"hook", "--policy", baseline}, strings.NewReader(catEnv), panicWriter{}, panicWriter{}, testEnv)
	}()
	if code != 2 {
		t.Errorf("both outputs panic: exit %d, want 2", code)
	}
}

func TestCheckCommand(t *testing.T) {
	if code, out, _ := call(t, "", "check", baseline, "../../examples/allow-listed.yaml"); code != 0 || strings.Count(out, "ok ") != 2 {
		t.Errorf("valid policies: exit %d %q", code, out)
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	os.WriteFile(bad, []byte("apiVersion: nope\n"), 0o600)
	if code, out, _ := call(t, "", "check", baseline, bad); code != 1 || !strings.Contains(out, "invalid "+bad) {
		t.Errorf("invalid policy: exit %d %q", code, out)
	}
	ign := filepath.Join(t.TempDir(), "ignore.yaml")
	if err := os.WriteFile(ign, []byte("apiVersion: "+brand.APIVersion+"\nkind: Policy\nmetadata: {name: ign}\nspec:\n  secrets: {ignore: [jwt, not-a-rule]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := call(t, "", "check", ign); code != 0 || !strings.Contains(out, `no rule "not-a-rule"`) || strings.Contains(out, `"jwt"`) {
		t.Errorf("check with an unknown ignored rule: exit %d, %q", code, out)
	}
	floor := filepath.Join(t.TempDir(), "floor.yaml")
	if err := os.WriteFile(floor, []byte("apiVersion: "+brand.APIVersion+"\nkind: Policy\nmetadata: {name: floor}\nspec: {minimumVersion: 1.4.2}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The test binary has no release version, so it meets no minimum.
	if code, out, _ := call(t, "", "check", floor); code != 0 || !strings.Contains(out, "minimumVersion: 1.4.2; the hook of this version (dev) would block every tool call") {
		t.Errorf("check with a minimum version: exit %d, %q", code, out)
	}
	if code, _, _ := call(t, "", "check"); code != 2 {
		t.Errorf("no arguments: exit %d", code)
	}
}

func TestExplainCommand(t *testing.T) {
	code, out, _ := call(t, "", "explain", "--policy", baseline, "--cwd", "/work/repo", "--home", "/home/dev", "--verbose",
		"--command", "sudo cat .env | grep KEY")
	if code != 0 || !strings.HasPrefix(out, "DENY  (files.deny[0])") || !strings.Contains(out, "[0] sudo cat .env") ||
		!strings.Contains(out, "↳ [0] cat .env") || !strings.Contains(out, "/work/repo/.env") {
		t.Errorf("explain: exit %d\n%s", code, out)
	}
	if code, out, _ := call(t, "", "explain", "--policy", baseline, "--json", "--mcp", "slack/post"); code != 0 || !strings.Contains(out, `"decision": "deny"`) {
		t.Errorf("explain json: exit %d %s", code, out)
	}
	if code, _, _ := call(t, "", "explain", "--policy", baseline, "--read", "a", "--write", "b"); code != 2 {
		t.Errorf("two actions: exit %d", code)
	}
	if code, _, _ := call(t, "", "explain", "--read", "a"); code != 2 {
		t.Errorf("no policy: exit %d", code)
	}
	code, out, errOut := call(t, "", "explain", "--policy", baseline, "--json", "--verbose", "--command", "cat .env")
	var v map[string]any
	if code != 0 || json.Unmarshal([]byte(out), &v) != nil || !strings.Contains(errOut, "cat .env") {
		t.Errorf("--json --verbose: exit %d\nstdout %s\nstderr %s", code, out, errOut)
	}
	if runtime.GOOS != "windows" {
		code, out, _ := call(t, "", "explain", "--policy", baseline, "--platform", "windows", "--cwd", `C:\work\repo`,
			"--home", `C:\Users\dev`, "--read", ".env")
		if code != 0 || !strings.HasPrefix(out, "DENY  (files.deny[0])") {
			t.Errorf("Windows paths on %s: exit %d\n%s", runtime.GOOS, code, out)
		}
	}
	// PowerShell: cat is Get-Content, shown as a second name of the command
	code, out, _ = call(t, "", "explain", "--policy", baseline, "--platform", "windows", "--cwd", `C:\work\repo`,
		"--home", `C:\Users\dev`, "--shell", "powershell", "--verbose", "--command", `cat .env`)
	if code != 0 || !strings.HasPrefix(out, "DENY  (files.deny[0])") || !strings.Contains(out, "↳ [0] Get-Content .env") {
		t.Errorf("--shell powershell: exit %d\n%s", code, out)
	}
	if code, _, _ := call(t, "", "explain", "--policy", baseline, "--shell", "powershell", "--read", "a"); code != 2 {
		t.Errorf("--shell with --read: exit %d", code)
	}
}

func TestExplainVerboseAliases(t *testing.T) {
	for _, tc := range []struct {
		name    string
		flags   []string
		verbose bool
	}{
		{"long", []string{"--verbose"}, true},
		{"short", []string{"-v"}, true},
		{"double-dash alias", []string{"--v"}, true},
		{"long false", []string{"--verbose=false"}, false},
		{"short false", []string{"-v=false"}, false},
		{"double-dash alias false", []string{"--v=false"}, false},
		{"double-dash alias overrides long", []string{"--verbose", "--v=false"}, false},
		{"long overrides short", []string{"-v", "--verbose=false"}, false},
		{"short overrides long", []string{"--verbose=false", "-v"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"explain", "--policy", baseline, "--json", "--command", "cat .env"}, tc.flags...)
			code, out, errs := call(t, "", args...)
			if code != 0 || !json.Valid([]byte(out)) || strings.Contains(errs, "\ncommands:\n") != tc.verbose {
				t.Fatalf("%v: exit %d, stdout %q, stderr %q", tc.flags, code, out, errs)
			}
		})
	}
}

// The exit code of the real process is what Claude Code sees
func TestBinaryExitCodes(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "cyberboar")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	absBaseline, _ := filepath.Abs(baseline)
	for _, tc := range []struct {
		name  string
		stdin string
		args  []string
		want  int
	}{
		{"deny", catEnv, []string{"hook", "--policy", absBaseline}, 2},
		{"no answer", lsSrc, []string{"hook", "--policy", absBaseline}, 0},
		{"bad flag", lsSrc, []string{"hook", "--bogus"}, 2},
		{"garbage input", "not json", []string{"hook", "--policy", absBaseline}, 2},
	} {
		cmd := exec.Command(bin, tc.args...)
		cmd.Stdin = strings.NewReader(tc.stdin)
		cmd.Env = []string{"CLAUDE_PROJECT_DIR=/work/repo", "HOME=/home/dev", "XDG_STATE_HOME=" + t.TempDir()}
		err := cmd.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		if code != tc.want {
			t.Errorf("%s: exit %d, want %d", tc.name, code, tc.want)
		}
	}
}

func TestHookCodexProtocol(t *testing.T) {
	in := `{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/work/repo","session_id":"s","turn_id":"1","tool_use_id":"c","model":"m","permission_mode":"default","transcript_path":null,"tool_input":{"command":"cat .env"}}`
	if code, out, errs := call(t, in, "hook", "-agent", "codex", "--policy", baseline); code != 0 || !strings.Contains(out, `"deny"`) || errs != "" {
		t.Errorf("codex deny: exit %d stdout %q stderr %q", code, out, errs)
	}
	plan := strings.Replace(strings.Replace(in, `"Bash"`, `"update_plan"`, 1), `{"command":"cat .env"}`, `{"plan":[]}`, 1)
	if code, out, _ := call(t, plan, "hook", "-agent", "codex", "--policy", baseline); code != 0 || out != "" {
		t.Errorf("codex no answer: exit %d stdout %q", code, out)
	}
}

func TestUnlock(t *testing.T) {
	state := t.TempDir()
	env := func(k string) string {
		if k == "XDG_STATE_HOME" {
			return state
		}
		return testEnv(k)
	}
	runCmd := func(stdin string, args ...string) (int, string) {
		var out, errb bytes.Buffer
		code := run(args, strings.NewReader(stdin), &out, &errb, env)
		return code, out.String() + errb.String()
	}
	in := func(cmd string) string {
		return `{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Bash","cwd":"/work/repo","tool_input":{"command":"` + cmd + `"}}`
	}
	for range 3 {
		runCmd(in("cat .env"), "hook", "--policy", advancedBaseline)
	}
	if code, out := runCmd(in("ls"), "hook", "--policy", advancedBaseline); code != 2 || !strings.Contains(out, "locked") {
		t.Fatalf("session not locked: exit %d %s", code, out)
	}
	if code, out := runCmd("", "unlock"); code != 0 || !strings.Contains(out, "claude-code s1  3 denied, last by files.deny[0]  LOCKED since ") {
		t.Fatalf("list: exit %d %q", code, out)
	}
	if code, out := runCmd("", "unlock", "-session", "s1"); code != 0 || !strings.Contains(out, "cleared claude-code session s1") {
		t.Fatalf("unlock: exit %d %q", code, out)
	}
	if code, out := runCmd(in("ls"), "hook", "--policy", advancedBaseline); code != 0 {
		t.Fatalf("still locked after unlock: exit %d %s", code, out)
	}
	if code, out := runCmd("", "unlock", "-all", "-session", "x"); code != 2 {
		t.Fatalf("-all with -session: exit %d %q", code, out)
	}
	runCmd(in("cat .env"), "hook", "--policy", advancedBaseline)
	if code, out := runCmd("", "unlock", "-all"); code != 0 || !strings.Contains(out, "cleared 1 sessions") {
		t.Fatalf("-all: exit %d %q", code, out)
	}
	if code, out := runCmd("", "unlock"); code != 0 || !strings.Contains(out, "no sessions") {
		t.Fatalf("empty list: exit %d %q", code, out)
	}
}

// The agent's environment can come from the project it opened, so the hook
// takes none of its configuration from it: not the policy or its key, not the
// audit log, not the state directory, and unlock agrees with the hook about the state
func TestHookIgnoresEnvironment(t *testing.T) {
	state := t.TempDir()
	env := func(k string) string {
		return map[string]string{
			"CLAUDE_PROJECT_DIR": "/work/repo", "HOME": "/home/dev", "XDG_STATE_HOME": state,
			envName("policy"): baseline, envName("pubkey"): "/nonexistent.pub",
			envName("audit"): "relative.jsonl", envName("state"): "relative/state",
		}[k]
	}
	call := func(stdin string, args ...string) (int, string) {
		var out, errb bytes.Buffer
		code := run(args, strings.NewReader(stdin), &out, &errb, env)
		return code, out.String() + errb.String()
	}
	// The variables would deny for a relative path or a missing key; ignored, the call passes
	if code, out := call(lsSrc, "hook", "--policy", baseline); code != 0 || out != "" {
		t.Errorf("hook with CYBERBOAR_* set: exit %d %q", code, out)
	}
	// CYBERBOAR_POLICY doesn't stand in for --policy: no policy, deny
	if code, out := call(lsSrc, "hook"); code != 2 || !strings.Contains(out, "no valid policy") {
		t.Errorf("hook without -policy: exit %d %q", code, out)
	}
	if code, out := call("", "brief"); code != 0 || strings.Contains(out, "do not try another way") {
		t.Errorf("brief briefed from CYBERBOAR_POLICY: exit %d %q", code, out)
	}
	if code, out := call("", "unlock"); code != 0 || !strings.Contains(out, "no sessions") {
		t.Errorf("unlock with CYBERBOAR_STATE set: exit %d %q", code, out)
	}
}

// A relative --state could point anywhere the agent's cwd leads: deny
func TestHookRelativeStateDenies(t *testing.T) {
	if code, out, _ := call(t, lsSrc, "hook", "--policy", baseline, "--state", "rel/dir"); code != 2 || !strings.Contains(out, "not an absolute path") {
		t.Fatalf("exit %d %q", code, out)
	}
}

func TestBrief(t *testing.T) {
	sessionStart := `{"hook_event_name":"SessionStart","session_id":"s","source":"startup","cwd":"/work/repo"}`
	code, out, errs := call(t, sessionStart, "brief", "-policy", baseline)
	if code != 0 || errs != "" || !strings.Contains(out, `"hookEventName":"SessionStart"`) || !strings.Contains(out, "do not try another way") {
		t.Fatalf("baseline: exit %d stdout %q stderr %q", code, out, errs)
	}
	off := filepath.Join(t.TempDir(), "off.yaml")
	data, _ := os.ReadFile(baseline)
	os.WriteFile(off, append(data, []byte("  session: {briefing: {enabled: false}}\n")...), 0o644)
	if code, out, _ := call(t, sessionStart, "brief", "-policy", off); code != 0 || out != "" {
		t.Fatalf("briefing off: exit %d stdout %q", code, out)
	}
	// Never blocks a session; says what will happen instead
	for _, args := range [][]string{
		{"brief", "-policy", "/nonexistent.yaml"},
		{"brief", "-policy", baseline, "-pubkey", "/nonexistent.pub"},
		{"brief", "-bogus"},
	} {
		code, out, _ := call(t, sessionStart, args...)
		if code != 0 || !strings.Contains(out, "additionalContext") {
			t.Errorf("%v: exit %d stdout %q", args, code, out)
		}
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

// An answer the agent never reads must not exit 0: for an ask, and for
// Cursor's deny, that would let the call run
func TestHookUnwritableAnswerDenies(t *testing.T) {
	gitPush := `{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/work/repo","tool_input":{"command":"git push"}}`
	cursorEnv := `{"hook_event_name":"beforeShellExecution","command":"cat .env","workspace_roots":["/work/repo"]}`
	for _, tc := range []struct {
		name, stdin string
		args        []string
	}{
		{"ask", gitPush, []string{"hook", "--policy", baseline}},
		{"cursor deny", cursorEnv, []string{"hook", "--agent", "cursor", "--policy", baseline}},
	} {
		var errb bytes.Buffer
		env := func(k string) string {
			if k == "XDG_STATE_HOME" {
				return t.TempDir()
			}
			return testEnv(k)
		}
		if code := run(tc.args, strings.NewReader(tc.stdin), brokenWriter{}, &errb, env); code != 2 || !strings.Contains(errb.String(), "can't write its answer") {
			t.Errorf("%s: exit %d stderr %q, want 2", tc.name, code, errb.String())
		}
	}
}

// A version from -ldflags wins; without one, the module version Go recorded
// stands in for "dev" unless there is none
func TestBuildVersion(t *testing.T) {
	mod := func(v string) *debug.BuildInfo {
		return &debug.BuildInfo{Main: debug.Module{Path: "cyberboar.dev/cyberboar", Version: v}}
	}
	for _, c := range []struct {
		v    string
		info *debug.BuildInfo
		ok   bool
		want string
	}{
		{"1.0.0", mod("v1.0.0-rc.1"), true, "1.0.0"},
		{"dev", mod("v1.0.0-rc.1"), true, "v1.0.0-rc.1"},
		{"dev", mod("v1.0.0-rc.1.0.20261017113155-6b7a4d9d9640+dirty"), true, "v1.0.0-rc.1.0.20261017113155-6b7a4d9d9640+dirty"},
		{"dev", mod("(devel)"), true, "dev"},
		{"dev", mod(""), true, "dev"},
		{"dev", nil, false, "dev"},
	} {
		if got := buildVersion(c.v, c.info, c.ok); got != c.want {
			t.Errorf("buildVersion(%q, %+v) = %q, want %q", c.v, c.info, got, c.want)
		}
	}
}
