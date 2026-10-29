package hook_test

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/adapters/claudecode"
	"cyberboar.dev/cyberboar/internal/adapters/codex"
	"cyberboar.dev/cyberboar/internal/adapters/copilot"
	"cyberboar.dev/cyberboar/internal/adapters/cursor"
	"cyberboar.dev/cyberboar/internal/adapters/opencode"
	"cyberboar.dev/cyberboar/internal/corpustest"
	"cyberboar.dev/cyberboar/internal/hook"
	"cyberboar.dev/cyberboar/internal/secrets/secretstest"
)

const casesPath = "testdata/claude-code/cases.yaml"

// adapterCases pairs each adapter with its end-to-end cases.
var adapterCases = []struct {
	path    string
	adapter adapters.Adapter
	check   func(t *testing.T, want string, r hook.Result) // the agent's hook contract
}{
	{casesPath, claudecode.Adapter{}, checkProtocol},
	{"testdata/codex/cases.yaml", codex.Adapter{}, checkCodexProtocol},
	{"testdata/copilot-cli/cases.yaml", copilot.Adapter{}, checkCopilotProtocol},
	{"testdata/cursor/cases.yaml", cursor.Adapter{}, checkCursorProtocol},
	{"testdata/opencode/cases.yaml", opencode.Adapter{}, checkOpencodeProtocol},
}

type caseFile struct {
	FS       []corpustest.FSEntry               `yaml:"fs"`
	Env      map[string]string                  `yaml:"env"`
	Defaults struct{ Input map[string]any }     `yaml:"defaults"`
	Policies map[string]corpustest.PolicySource `yaml:"policies"`
	Cases    []hookCase                         `yaml:"cases"`
}

type hookCase struct {
	Name     string            `yaml:"name"`
	Policy   string            `yaml:"policy"`
	Env      map[string]string `yaml:"env"`
	Input    map[string]any    `yaml:"input"`
	RawInput *string           `yaml:"rawInput"`
	// GOOS lists the operating systems (runtime.GOOS values) the case runs
	// on, for an adapter that reads the one it runs on. Empty means every one.
	GOOS   []string `yaml:"goos"`
	Expect struct {
		Decision       string `yaml:"decision"` // what the agent is told: deny | ask | none
		Verdict        string `yaml:"verdict"`  // the engine verdict, when it differs (Codex: ask → deny)
		Rule           string `yaml:"rule"`
		ReasonContains string `yaml:"reasonContains"`
		// NoticeContains is part of what the user is told as well (Claude
		// Code's systemMessage). Without it, no notice may be given.
		NoticeContains string `yaml:"noticeContains"`
	} `yaml:"expect"`
}

// expandFakes replaces {{fake:RULE}} in every string of an input with a
// made-up credential (secretstest), before the input becomes JSON: a
// credential can span lines.
func expandFakes(v any) any {
	switch v := v.(type) {
	case string:
		return secretstest.Expand(v)
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, e := range v {
			out[k] = expandFakes(e)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			out[i] = expandFakes(e)
		}
		return out
	}
	return v
}

func TestHookCorpus(t *testing.T) {
	for _, ac := range adapterCases {
		t.Run(ac.adapter.Name(), func(t *testing.T) { runCases(t, ac.path, ac.adapter, ac.check) })
	}
}

func runCases(t *testing.T, casesPath string, adapter adapters.Adapter, check func(*testing.T, string, hook.Result)) {
	data, err := os.ReadFile(casesPath)
	if err != nil {
		t.Fatal(err)
	}
	var cf caseFile
	if err := yaml.UnmarshalWithOptions(data, &cf, yaml.Strict()); err != nil {
		t.Fatal(yaml.FormatError(err, false, true))
	}
	fixture := &corpustest.File{Path: casesPath, FS: cf.FS, Policies: cf.Policies}
	root, err := fixture.BuildFixture()
	t.Cleanup(func() { os.RemoveAll(root) })
	if err != nil {
		t.Fatal(err)
	}
	sub := func(s string) string { return strings.ReplaceAll(s, "{{root}}", root) }

	for _, c := range cf.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if len(c.GOOS) > 0 && !slices.Contains(c.GOOS, runtime.GOOS) {
				t.Skipf("runs on %v only", c.GOOS)
			}
			pol, err := fixture.PolicyBytes(c.Policy, root)
			if err != nil {
				t.Fatal(err)
			}
			env := map[string]string{}
			for k, v := range cf.Env {
				env[k] = sub(v)
			}
			for k, v := range c.Env {
				env[k] = sub(v)
			}
			var stdin []byte
			if c.RawInput != nil {
				stdin = []byte(*c.RawInput)
			} else {
				merged := map[string]any{}
				maps.Copy(merged, cf.Defaults.Input)
				maps.Copy(merged, c.Input)
				js, err := json.Marshal(expandFakes(merged))
				if err != nil {
					t.Fatal(err)
				}
				stdin = []byte(sub(string(js)))
			}

			r := hook.Run(context.Background(), bytes.NewReader(stdin), hook.Options{Adapter: adapter,
				PolicyPath: policyFile(t, pol, nil), Getenv: func(k string) string { return env[k] }, Version: "test", StateDir: t.TempDir()})
			t.Logf("exit %d, verdict %s by %s: %s", r.Exit, r.Verdict.Decision, r.Verdict.Rule, r.Verdict.Reason)
			check(t, c.Expect.Decision, r)
			if c.Expect.Verdict != "" && string(r.Verdict.Decision) != c.Expect.Verdict {
				t.Errorf("want engine verdict %s, got %s", c.Expect.Verdict, r.Verdict.Decision)
			}
			if c.Expect.Rule != "" && r.Verdict.Rule != c.Expect.Rule {
				t.Errorf("want rule %q, got %q", c.Expect.Rule, r.Verdict.Rule)
			}
			if !strings.Contains(r.Verdict.Reason, c.Expect.ReasonContains) {
				t.Errorf("want reason containing %q, got %q", c.Expect.ReasonContains, r.Verdict.Reason)
			}
			switch n := r.Verdict.Notice; {
			case c.Expect.NoticeContains == "" && n != "":
				t.Errorf("want no notice for the user, got %q", n)
			case !strings.Contains(n, c.Expect.NoticeContains):
				t.Errorf("want a notice for the user containing %q, got %q", c.Expect.NoticeContains, n)
			}
		})
	}
}

// checkProtocol asserts the exact Claude Code hook contract for a decision.
func checkProtocol(t *testing.T, want string, r hook.Result) {
	t.Helper()
	checkHookSpecificOutput(t, want, r, 2)
}

// checkCodexProtocol asserts Codex's contract: Claude Code's JSON, but a deny
// exits 0 with nothing on stderr, since PowerShell turns a hook's exit 2 into
// 1, which Codex treats as a failed hook.
func checkCodexProtocol(t *testing.T, want string, r hook.Result) {
	t.Helper()
	checkHookSpecificOutput(t, want, r, 0)
}

// checkHookSpecificOutput asserts the hookSpecificOutput answer, with a deny
// exiting denyExit; a deny that exits 2 also gives its reason on stderr.
func checkHookSpecificOutput(t *testing.T, want string, r hook.Result, denyExit int) {
	t.Helper()
	if want == "none" {
		if r.Exit != 0 || len(r.Stdout) != 0 || r.Stderr != "" {
			t.Fatalf("want no answer, got exit %d stdout %q stderr %q", r.Exit, r.Stdout, r.Stderr)
		}
		return
	}
	wantExit := map[string]int{"deny": denyExit, "ask": 0}[want]
	if r.Exit != wantExit {
		t.Errorf("want exit %d, got %d", wantExit, r.Exit)
	}
	var out struct {
		HSO struct {
			Event    string `json:"hookEventName"`
			Decision string `json:"permissionDecision"`
			Reason   string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
		SystemMessage *string `json:"systemMessage"`
	}
	dec := json.NewDecoder(bytes.NewReader(r.Stdout))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("stdout is not the hook JSON: %v (%q)", err, r.Stdout)
	}
	if out.HSO.Event != "PreToolUse" || out.HSO.Decision != want || out.HSO.Reason == "" {
		t.Errorf("unexpected hook JSON %+v", out.HSO)
	}
	switch {
	case want == "deny" && denyExit == 2 && !strings.Contains(r.Stderr, out.HSO.Reason):
		t.Errorf("deny reason not on stderr: %q", r.Stderr)
	case want == "deny" && denyExit == 0 && r.Stderr != "":
		t.Errorf("stderr %q beside a deny that exits 0", r.Stderr)
	}
	// The user sees systemMessage; it is there exactly when there is a notice.
	switch msg := out.SystemMessage; {
	case r.Verdict.Notice == "" && msg != nil:
		t.Errorf("systemMessage %q without a notice", *msg)
	case r.Verdict.Notice != "" && (msg == nil || *msg != r.Verdict.Notice):
		t.Errorf("systemMessage %v, want the notice %q", msg, r.Verdict.Notice)
	}
}

// checkCopilotProtocol asserts Copilot CLI's preToolUse contract: deny exits
// 2 with the JSON decision (Copilot shows its reason) and the reason on
// stderr; ask exits 0 with the JSON decision.
// The same decision is in hookSpecificOutput, for VS Code's Local agent.
func checkCopilotProtocol(t *testing.T, want string, r hook.Result) {
	t.Helper()
	if want == "none" {
		if r.Exit != 0 || len(r.Stdout) != 0 || r.Stderr != "" {
			t.Fatalf("want no answer, got exit %d stdout %q stderr %q", r.Exit, r.Stdout, r.Stderr)
		}
		return
	}
	wantExit := map[string]int{"deny": 2, "ask": 0}[want]
	if r.Exit != wantExit {
		t.Errorf("want exit %d, got %d", wantExit, r.Exit)
	}
	type decision struct {
		Event    string `json:"hookEventName,omitempty"`
		Decision string `json:"permissionDecision"`
		Reason   string `json:"permissionDecisionReason"`
	}
	var out struct {
		decision
		Specific decision `json:"hookSpecificOutput"`
	}
	dec := json.NewDecoder(bytes.NewReader(r.Stdout))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("stdout is not the hook JSON: %v (%q)", err, r.Stdout)
	}
	if out.Decision != want || out.Reason == "" || out.Event != "" {
		t.Errorf("unexpected hook JSON %+v", out)
	}
	if out.Specific != (decision{"PreToolUse", out.Decision, out.Reason}) {
		t.Errorf("hookSpecificOutput %+v differs from the top-level answer", out.Specific)
	}
	if want == "deny" && !strings.Contains(r.Stderr, out.Reason) {
		t.Errorf("deny reason not on stderr: %q", r.Stderr)
	}
}

// checkCursorProtocol asserts Cursor's hook contract: always exit 0 and JSON
// (invalid JSON would block), "{}" for no decision, a deny with its reason.
func checkCursorProtocol(t *testing.T, want string, r hook.Result) {
	t.Helper()
	if r.Exit != 0 {
		t.Errorf("want exit 0, got %d", r.Exit)
	}
	if want == "none" {
		if string(r.Stdout) != "{}\n" || r.Stderr != "" {
			t.Fatalf("want no decision, got stdout %q stderr %q", r.Stdout, r.Stderr)
		}
		return
	}
	var out struct {
		Permission   string `json:"permission"`
		UserMessage  string `json:"user_message"`
		AgentMessage string `json:"agent_message"`
	}
	dec := json.NewDecoder(bytes.NewReader(r.Stdout))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("stdout is not the hook JSON: %v (%q)", err, r.Stdout)
	}
	if want != "deny" || out.Permission != "deny" || out.UserMessage == "" || out.AgentMessage != out.UserMessage {
		t.Errorf("want %s, got hook JSON %+v", want, out)
	}
	if !strings.Contains(r.Stderr, out.UserMessage) {
		t.Errorf("deny reason not on stderr: %q", r.Stderr)
	}
}

// checkOpencodeProtocol asserts the plugin shim's contract: the call goes
// through only on exit 0 with exactly {"decision":"none"}; deny exits 2 with
// {"decision":"deny","reason":…} and the reason on stderr. There is no ask:
// opencode plugins can't ask the user.
func checkOpencodeProtocol(t *testing.T, want string, r hook.Result) {
	t.Helper()
	if want == "none" {
		if r.Exit != 0 || string(r.Stdout) != `{"decision":"none"}`+"\n" || r.Stderr != "" {
			t.Fatalf("want no objection, got exit %d stdout %q stderr %q", r.Exit, r.Stdout, r.Stderr)
		}
		return
	}
	if want != "deny" {
		t.Fatalf("opencode answers only none or deny, not %s", want)
	}
	if r.Exit != 2 {
		t.Errorf("want exit 2, got %d", r.Exit)
	}
	var out struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	dec := json.NewDecoder(bytes.NewReader(r.Stdout))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("stdout is not the hook JSON: %v (%q)", err, r.Stdout)
	}
	if out.Decision != "deny" || out.Reason == "" {
		t.Errorf("unexpected hook JSON %+v", out)
	}
	if !strings.Contains(r.Stderr, out.Reason) {
		t.Errorf("deny reason not on stderr: %q", r.Stderr)
	}
}
