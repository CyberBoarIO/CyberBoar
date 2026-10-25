package hook_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/adapters/claudecode"
	"cyberboar.dev/cyberboar/internal/adapters/codex"
	"cyberboar.dev/cyberboar/internal/adapters/copilot"
	"cyberboar.dev/cyberboar/internal/adapters/cursor"
	"cyberboar.dev/cyberboar/internal/adapters/opencode"
	"cyberboar.dev/cyberboar/internal/engine"
	"cyberboar.dev/cyberboar/internal/hook"
	"cyberboar.dev/cyberboar/internal/secrets/secretstest"
	"cyberboar.dev/cyberboar/pkg/audit"
	"cyberboar.dev/cyberboar/pkg/brand"
	"cyberboar.dev/cyberboar/pkg/sign"
)

const bashLS = `{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/work/repo","tool_input":{"command":"ls"}}`

func baselinePolicy(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../../examples/baseline.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func env(k string) string {
	return map[string]string{"CLAUDE_PROJECT_DIR": "/work/repo", "HOME": "/home/dev"}[k]
}

// policyFile writes a policy document, and its signature unless sig is
// nil, to a new directory and returns the policy's path.
func policyFile(t *testing.T, data, sig []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if sig != nil {
		if err := os.WriteFile(path+sign.SigSuffix, sig, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// blockingReader is hook input that never arrives until release is closed:
// an evaluation stuck on a hung filesystem.
type blockingReader struct{ release <-chan struct{} }

func (r blockingReader) Read([]byte) (int, error) {
	<-r.release
	return 0, io.ErrUnexpectedEOF
}

// panickingReader is hook input whose reading panics.
type panickingReader struct{}

func (panickingReader) Read([]byte) (int, error) { panic("boom") }

func assertDenied(t *testing.T, r hook.Result, rule string) {
	t.Helper()
	if r.Exit != 2 || r.Verdict.Decision != engine.Deny || r.Verdict.Rule != rule {
		t.Fatalf("want deny by %s with exit 2, got exit %d %s by %s (%s)", rule, r.Exit, r.Verdict.Decision, r.Verdict.Rule, r.Verdict.Reason)
	}
}

// The agent's own hook timeout fails open, so the hook must answer first.
func TestDeadlineDenies(t *testing.T) {
	// The evaluation is abandoned, not stopped; let it end with the test.
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	start := time.Now()
	r := hook.Run(context.Background(), blockingReader{release}, hook.Options{Adapter: cc, StateDir: t.TempDir(),
		PolicyPath: policyFile(t, baselinePolicy(t), nil), Getenv: env, Deadline: 50 * time.Millisecond})
	assertDenied(t, r, engine.RuleDeadline)
	if took := time.Since(start); took > time.Second {
		t.Errorf("hook answered after %s; the deadline must not wait for the evaluation", took)
	}
}

func TestPanicDenies(t *testing.T) {
	r := hook.Run(context.Background(), panickingReader{}, hook.Options{Adapter: cc, StateDir: t.TempDir(), PolicyPath: policyFile(t, baselinePolicy(t), nil), Getenv: env})
	assertDenied(t, r, engine.RuleInternal)
}

func TestMissingPolicyFileDenies(t *testing.T) {
	for _, path := range []string{"", filepath.Join(t.TempDir(), "missing.yaml")} {
		r := hook.Run(context.Background(), strings.NewReader(bashLS), hook.Options{Adapter: cc, StateDir: t.TempDir(), PolicyPath: path, Getenv: env})
		assertDenied(t, r, engine.RuleNoPolicy)
	}
}

func TestInputTooLargeDenies(t *testing.T) {
	big := strings.NewReader(strings.Repeat(" ", hook.MaxInput+1))
	r := hook.Run(context.Background(), big, hook.Options{Adapter: cc, StateDir: t.TempDir(), PolicyPath: policyFile(t, baselinePolicy(t), nil), Getenv: env})
	assertDenied(t, r, hook.RuleInputTooLarge)
}

func TestAuditEvent(t *testing.T) {
	log := filepath.Join(t.TempDir(), "sub", "audit.jsonl")
	in := `{"hook_event_name":"PreToolUse","session_id":"s1","tool_use_id":"t1","tool_name":"Bash","cwd":"/work/repo","tool_input":{"command":"cat .env"}}`
	r := hook.Run(context.Background(), strings.NewReader(in), hook.Options{Adapter: cc, StateDir: t.TempDir(),
		PolicyPath: policyFile(t, baselinePolicy(t), nil), Getenv: env, AuditPath: log, Version: "v-test"})
	assertDenied(t, r, "files.deny[0]")

	f, err := os.Open(log)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if info, _ := f.Stat(); info.Mode().Perm() != 0o600 {
		t.Errorf("audit log mode %v, want 0600", info.Mode().Perm())
	}
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		t.Fatal("no audit line")
	}
	var ev audit.Event
	if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Decision != "deny" || ev.Rule != "files.deny[0]" || ev.Session != "s1" || ev.ToolUseID != "t1" ||
		ev.Tool != "Bash" || ev.Project != "/work/repo" || ev.PolicyName != "baseline" || len(ev.PolicyHash) != 64 ||
		ev.Version != "v-test" || len(ev.Actions) != 1 || ev.Actions[0].Command != "cat .env" || ev.Time == "" {
		t.Errorf("unexpected audit event: %+v", ev)
	}
}

// No audit trail, no action.
func TestAuditFailureDenies(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r := hook.Run(context.Background(), strings.NewReader(bashLS), hook.Options{Adapter: cc, StateDir: t.TempDir(),
		PolicyPath: policyFile(t, baselinePolicy(t), nil), Getenv: env, AuditPath: filepath.Join(blocker, "audit.jsonl")})
	assertDenied(t, r, hook.RuleAudit)
}

// The agent can't empty the audit log or append invented events to it.
func TestAuditLogIsProtected(t *testing.T) {
	log := filepath.Join(t.TempDir(), "logs", "audit.jsonl")
	for _, in := range []string{
		fmt.Sprintf(`{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/work/repo","tool_input":{"command":"truncate -s0 %s"}}`, log),
		fmt.Sprintf(`{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/work/repo","tool_input":{"command":"echo {} >> %s"}}`, log),
		fmt.Sprintf(`{"hook_event_name":"PreToolUse","tool_name":"Write","cwd":"/work/repo","tool_input":{"file_path":%q,"content":""}}`, log),
	} {
		r := hook.Run(context.Background(), strings.NewReader(in), hook.Options{Adapter: cc, StateDir: t.TempDir(),
			PolicyPath: policyFile(t, baselinePolicy(t), nil), Getenv: env, AuditPath: log})
		assertDenied(t, r, engine.RuleSelf)
	}
}

var cc = claudecode.Adapter{}

func TestNoAdapterDenies(t *testing.T) {
	r := hook.Run(context.Background(), strings.NewReader(bashLS), hook.Options{PolicyPath: policyFile(t, baselinePolicy(t), nil), Getenv: env})
	assertDenied(t, r, hook.RuleNoAdapter)
}

func TestPolicySignature(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath := filepath.Join(dir, "k"), filepath.Join(dir, "k.pub")
	if err := sign.Keygen(privPath, pubPath); err != nil {
		t.Fatal(err)
	}
	priv, _ := sign.LoadPrivate(privPath)
	pub, _ := sign.LoadPublic(pubPath)
	pol := baselinePolicy(t)
	now := time.Now().UTC().Truncate(time.Second)
	h := sign.Header{Serial: 1, Expires: now.Add(time.Hour)}
	goodSig, err := sign.Sign(priv, "baseline", pol, h)
	if err != nil {
		t.Fatal(err)
	}
	good := []byte(goodSig)
	run := func(policyData, sig []byte) hook.Result {
		return hook.Run(context.Background(), strings.NewReader(bashLS), hook.Options{Adapter: cc, StateDir: t.TempDir(),
			PolicyPath: policyFile(t, policyData, sig), PublicKey: pub, Getenv: env, Now: func() time.Time { return now }})
	}
	if r := run(pol, good); r.Exit != 0 || r.Verdict.Decision == engine.Deny {
		t.Fatalf("signed policy: %+v", r.Verdict)
	}
	assertDenied(t, run(append(pol, "# edited\n"...), good), hook.RuleSignature)
	assertDenied(t, run(pol, []byte("AAAA")), hook.RuleSignature)
	// Removing the headers must invalidate a signature
	_, raw, err := sign.Parse(good)
	if err != nil {
		t.Fatal(err)
	}
	bare := base64.StdEncoding.EncodeToString(raw) + "\n"
	assertDenied(t, run(pol, []byte(bare)), hook.RuleSignature)
	// From the expiry on, every call is denied.
	now = h.Expires.Add(-time.Second)
	if r := run(pol, good); r.Exit != 0 {
		t.Fatalf("a second before expiry: %+v", r.Verdict)
	}
	for _, at := range []time.Time{h.Expires, h.Expires.AddDate(1, 0, 0)} {
		now = at
		r := run(pol, good)
		assertDenied(t, r, hook.RulePolicyExpired)
		if !strings.Contains(r.Verdict.Reason, h.Expires.Format(time.RFC3339)) || !strings.Contains(r.Verdict.Reason, "pull") {
			t.Errorf("expired reason: %s", r.Verdict.Reason)
		}
		if b := string(hook.Brief(hook.Options{PolicyPath: policyFile(t, pol, good), PublicKey: pub, Now: func() time.Time { return at }})); !strings.Contains(b, "expired") {
			t.Errorf("briefing of an expired policy: %s", b)
		}
	}
	// A policy signed without expiry never expires.
	forever, err := sign.Sign(priv, "baseline", pol, sign.Header{Serial: 2})
	if err != nil {
		t.Fatal(err)
	}
	now = h.Expires.AddDate(100, 0, 0)
	if r := run(pol, []byte(forever)); r.Exit != 0 {
		t.Fatalf("a policy without expiry: %+v", r.Verdict)
	}
	now = h.Expires.Add(-time.Hour)
	// From files: a missing .sig denies; a matching one is used.
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, pol, 0o600); err != nil {
		t.Fatal(err)
	}
	runFile := func() hook.Result {
		return hook.Run(context.Background(), strings.NewReader(bashLS), hook.Options{Adapter: cc, StateDir: t.TempDir(), PolicyPath: path, PublicKey: pub, Getenv: env,
			Now: func() time.Time { return now }})
	}
	assertDenied(t, runFile(), hook.RuleSignature)
	if err := os.WriteFile(path+sign.SigSuffix, good, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := runFile(); r.Exit != 0 {
		t.Fatalf("signed policy file: %+v", r.Verdict)
	}
	now = h.Expires
	assertDenied(t, runFile(), hook.RulePolicyExpired)
}

// The engine implements POSIX and Windows path semantics; on any other
// operating system, and for Codex, Copilot CLI, Cursor and opencode on
// Windows (PowerShell), every call is denied rather than checked with the
// wrong ones.
func TestUnsupportedPlatformDenies(t *testing.T) {
	for _, goos := range []string{"plan9", "js"} {
		r := hook.Run(context.Background(), strings.NewReader(bashLS), hook.Options{GOOS: goos, Adapter: cc, StateDir: t.TempDir(), PolicyPath: policyFile(t, baselinePolicy(t), nil), Getenv: env})
		assertDenied(t, r, hook.RuleUnsupportedPlatform)
	}
	goos := "windows"
	r := hook.Run(context.Background(), strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"C:\\work\\repo","tool_input":{"command":"dir"}}`),
		hook.Options{GOOS: goos, Adapter: codex.Adapter{}, StateDir: t.TempDir(), PolicyPath: policyFile(t, baselinePolicy(t), nil), Getenv: env})
	assertDenied(t, r, hook.RuleUnsupportedPlatform)
	// Only the user can fix it, so the user is told too, not only the agent.
	var out struct{ SystemMessage string }
	if err := json.Unmarshal(r.Stdout, &out); err != nil || out.SystemMessage != r.Verdict.Reason {
		t.Errorf("the user isn't told why every call is blocked: %q (%v)", r.Stdout, err)
	}
	r = hook.Run(context.Background(), strings.NewReader(`{"sessionId":"s","cwd":"C:\\work\\repo","toolName":"powershell","toolArgs":{"command":"dir"}}`),
		hook.Options{GOOS: goos, Adapter: copilot.Adapter{}, StateDir: t.TempDir(), PolicyPath: policyFile(t, baselinePolicy(t), nil), Getenv: env})
	assertDenied(t, r, hook.RuleUnsupportedPlatform)
	// The user must be told why and where to go instead.
	for _, want := range []string{"Copilot CLI", "native Windows", "PowerShell", "WSL"} {
		if !strings.Contains(r.Verdict.Reason, want) {
			t.Errorf("Copilot on Windows: reason %q doesn't mention %q", r.Verdict.Reason, want)
		}
	}
	r = hook.Run(context.Background(), strings.NewReader(`{"hook_event_name":"beforeShellExecution","conversation_id":"c","workspace_roots":["C:\\work\\repo"],"command":"dir","cwd":"C:\\work\\repo"}`),
		hook.Options{GOOS: goos, Adapter: cursor.Adapter{}, StateDir: t.TempDir(), PolicyPath: policyFile(t, baselinePolicy(t), nil), Getenv: env})
	// Cursor's deny is JSON with exit 0.
	if r.Verdict.Decision != engine.Deny || r.Verdict.Rule != hook.RuleUnsupportedPlatform || !strings.Contains(string(r.Stdout), `"permission":"deny"`) {
		t.Errorf("Cursor on Windows: %+v %s", r.Verdict, r.Stdout)
	}
	if !strings.Contains(r.Verdict.Reason, "Cursor runs its commands in PowerShell") {
		t.Errorf("Cursor on Windows: reason %q", r.Verdict.Reason)
	}
	// opencode runs PowerShell on Windows unless $SHELL or its config names
	// another shell; a Git Bash one is denied too.
	for _, in := range []string{
		`{"tool":"bash","sessionID":"s","callID":"c","args":{"command":"dir"},"directory":"C:\\work\\repo","worktree":"C:\\work\\repo","shell":"","mcpServers":[]}`,
		`{"tool":"read","sessionID":"s","callID":"c","args":{"filePath":"README.md"},"directory":"C:\\work\\repo","worktree":"C:\\work\\repo","shell":"C:\\Program Files\\Git\\bin\\bash.exe","mcpServers":[]}`,
	} {
		r = hook.Run(context.Background(), strings.NewReader(in),
			hook.Options{GOOS: goos, Adapter: opencode.Adapter{}, StateDir: t.TempDir(), PolicyPath: policyFile(t, baselinePolicy(t), nil), Getenv: env})
		assertDenied(t, r, hook.RuleUnsupportedPlatform)
		for _, want := range []string{"opencode", "native Windows", "PowerShell", "WSL"} {
			if !strings.Contains(r.Verdict.Reason, want) {
				t.Errorf("opencode on Windows: reason %q doesn't mention %q", r.Verdict.Reason, want)
			}
		}
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		if !hook.PlatformSupported(goos, "claude-code") {
			t.Errorf("claude-code on %s must be supported", goos)
		}
	}
}

// A policy may require a minimum release; an older hook, or one whose
// version can't be placed, denies every call and tells the user why
func TestMinimumVersion(t *testing.T) {
	pol := []byte("apiVersion: " + brand.APIVersion + "\nkind: Policy\nmetadata: {name: floor}\nspec: {minimumVersion: v1.4.2}\n")
	for _, tc := range []struct {
		version string
		denied  bool
	}{
		{"1.4.2", false},
		{"v1.4.2", false},
		{"1.5.0", false},
		{"1.4.3-SNAPSHOT-a1b2c3d", false},
		{"1.4.1", true},
		{"1.4.2-rc.1", true},
		{"0.99.0", true},
		{"dev", true},
		{"", true},
	} {
		r := hook.Run(context.Background(), strings.NewReader("{}"), hook.Options{Adapter: requiredKeyAdapter{cc}, StateDir: t.TempDir(),
			PolicyPath: policyFile(t, pol, nil), Getenv: env, Version: tc.version})
		if !tc.denied {
			if r.Verdict.Decision == engine.Deny {
				t.Errorf("version %q: denied by %s (%s)", tc.version, r.Verdict.Rule, r.Verdict.Reason)
			}
			continue
		}
		assertDenied(t, r, hook.RuleVersion)
		if !strings.Contains(r.Verdict.Reason, "v1.4.2 or later") {
			t.Errorf("version %q: reason %q doesn't name the minimum", tc.version, r.Verdict.Reason)
		}
		var out struct{ SystemMessage string }
		if err := json.Unmarshal(r.Stdout, &out); err != nil || out.SystemMessage != r.Verdict.Reason {
			t.Errorf("version %q: the user isn't told why every call is blocked: %q (%v)", tc.version, r.Stdout, err)
		}
	}
	// Without a minimum, a build without a release version enforces as usual.
	r := hook.Run(context.Background(), strings.NewReader("{}"), hook.Options{Adapter: requiredKeyAdapter{cc}, StateDir: t.TempDir(),
		PolicyPath: policyFile(t, baselinePolicy(t), nil), Getenv: env, Version: "dev"})
	if r.Verdict.Decision == engine.Deny {
		t.Errorf("no minimum: denied by %s (%s)", r.Verdict.Rule, r.Verdict.Reason)
	}
}

// Outside native Windows the PowerShell tool can't be checked, so every call
// is denied whatever the policy says. The agent is sent to the Bash tool,
// where the same command is checked, and the user is told why
func TestPowerShellPointsToBash(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("on native Windows PowerShell is analysed")
	}
	powershell := `{"hook_event_name":"PreToolUse","tool_name":"PowerShell","cwd":"/work/repo","tool_input":{"command":"Get-ChildItem"}}`
	interp := []byte("apiVersion: " + brand.APIVersion + "\nkind: Policy\nmetadata: {name: p}\nspec: {commands: {denyInterpreters: false}}\n")
	for _, pol := range [][]byte{baselinePolicy(t), interp} {
		r := hook.Run(context.Background(), strings.NewReader(powershell), hook.Options{Adapter: cc, StateDir: t.TempDir(), PolicyPath: policyFile(t, pol, nil), Getenv: env})
		assertDenied(t, r, adapters.RulePowerShell)
		if !strings.Contains(r.Verdict.Reason, "Bash tool") || strings.Contains(r.Verdict.Reason, "do not attempt") {
			t.Errorf("reason: %s", r.Verdict.Reason)
		}
		if !strings.Contains(r.Verdict.Notice, "PowerShell") || !strings.Contains(string(r.Stdout), `"systemMessage"`) {
			t.Errorf("the user isn't told: notice %q, stdout %s", r.Verdict.Notice, r.Stdout)
		}
	}
	// The audit log keeps the blocked PowerShell command.
	log := filepath.Join(t.TempDir(), "audit.jsonl")
	hook.Run(context.Background(), strings.NewReader(powershell), hook.Options{Adapter: cc, StateDir: t.TempDir(), PolicyPath: policyFile(t, baselinePolicy(t), nil), Getenv: env, AuditPath: log})
	data, err := os.ReadFile(log)
	var ev audit.Event
	if err == nil {
		err = json.Unmarshal(data, &ev)
	}
	if err != nil || ev.Rule != adapters.RulePowerShell || len(ev.Actions) != 1 || !strings.Contains(ev.Actions[0].Command, "Get-ChildItem") {
		t.Errorf("audit event %+v (%v)", ev, err)
	}

	r := hook.Run(context.Background(), strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/work/repo","tool_input":{"command":"python -c 1"}}`),
		hook.Options{Adapter: cc, StateDir: t.TempDir(), PolicyPath: policyFile(t, baselinePolicy(t), nil), Getenv: env})
	if strings.Contains(r.Verdict.Reason, "Bash tool") || r.Verdict.Notice != "" {
		t.Errorf("Bash's own inline code treated as PowerShell: %+v", r.Verdict)
	}
}

// The audit log is kept and shipped: it never holds a credential the hook
// saw, whether the policy acts on secrets or not
func TestAuditRedactsSecrets(t *testing.T) {
	secret, _ := secretstest.Fake("github-pat")
	off := strings.Replace(string(baselinePolicy(t)), "\nspec:\n", "\nspec:\n  secrets: {action: \"off\"}\n", 1)
	if off == string(baselinePolicy(t)) {
		t.Fatal("couldn't turn secrets off in the baseline policy")
	}
	for _, how := range []string{"", "sq", "base64", "hex"} {
		hidden := secret
		if how != "" {
			hidden, _ = secretstest.Hide(secret, how)
		}
		cmd, _ := json.Marshal("GH=" + hidden + " ./publish " + strings.Repeat("a", 5000))
		in := `{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Bash","cwd":"/work/repo","tool_input":{"command":` + string(cmd) + `}}`
		for _, tc := range []struct {
			policy string
			rule   string
		}{{string(baselinePolicy(t)), "secrets.github-pat"}, {off, ""}} {
			log := filepath.Join(t.TempDir(), "audit.jsonl")
			r := hook.Run(context.Background(), strings.NewReader(in), hook.Options{Adapter: cc, StateDir: t.TempDir(),
				PolicyPath: policyFile(t, []byte(tc.policy), nil), Getenv: env, AuditPath: log, Version: "v-test"})
			if tc.rule != "" {
				assertDenied(t, r, tc.rule)
			}
			data, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), secret[4:]) || strings.Contains(string(data), hidden[4:]) ||
				!strings.Contains(string(data), "[REDACTED:github-pat]") {
				t.Errorf("%q, rule %q: the audit line isn't redacted: %.300s", how, tc.rule, data)
			}
		}
	}
}

// Every field the agent wrote is redacted, not only the command and paths.
func TestAuditRedactsEveryField(t *testing.T) {
	secret, _ := secretstest.Fake("github-pat")
	in := `{"hook_event_name":"PreToolUse","session_id":"s-` + secret + `","tool_use_id":"` + secret + `","permission_mode":"` + secret +
		`","tool_name":"Bash","cwd":"/work/` + secret + `","tool_input":{"command":"true"}}`
	log := filepath.Join(t.TempDir(), "audit.jsonl")
	hook.Run(context.Background(), strings.NewReader(in), hook.Options{Adapter: cc, StateDir: t.TempDir(),
		PolicyPath: policyFile(t, baselinePolicy(t), nil), Getenv: env, AuditPath: log, Version: "v-test"})
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret[4:]) || strings.Count(string(data), "[REDACTED:github-pat]") < 4 {
		t.Errorf("the audit line isn't redacted: %s", data)
	}

	in = `{"hook_event_name":"PreToolUse","session_id":"s","tool_use_id":"t","tool_name":"mcp__` + secret + `__create","cwd":"/work","tool_input":{}}`
	hook.Run(context.Background(), strings.NewReader(in), hook.Options{Adapter: cc, StateDir: t.TempDir(),
		PolicyPath: policyFile(t, baselinePolicy(t), nil), Getenv: env, AuditPath: log, Version: "v-test"})
	if data, err = os.ReadFile(log); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret[4:]) {
		t.Errorf("the MCP server isn't redacted: %s", data)
	}
}
