package hook_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/adapters/claudecode"
	"cyberboar.dev/cyberboar/internal/engine"
	"cyberboar.dev/cyberboar/internal/hook"
	"cyberboar.dev/cyberboar/internal/hook/tripwire"
	"cyberboar.dev/cyberboar/internal/secrets/secretstest"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// sessionPolicy is the baseline's rules with the given spec.session
func sessionPolicy(session string) []byte {
	return []byte(`apiVersion: ` + brand.APIVersion + `
kind: Policy
metadata: {name: tripwire-test}
spec:
  files:
    deny: ["**/.env*"]
    ask: ["**/terraform.tfstate"]
  commands:
    deny: ["terraform apply"]
  session: ` + session + "\n")
}

func bash(session, command string) string {
	return fmt.Sprintf(`{"hook_event_name":"PreToolUse","session_id":%q,"tool_name":"Bash","cwd":"/work/repo","tool_input":{"command":%q}}`, session, command)
}

type hookRig struct {
	t      *testing.T
	policy []byte
	state  string
}

func (h hookRig) run(input string) hook.Result {
	h.t.Helper()
	return hook.Run(context.Background(), strings.NewReader(input), hook.Options{Adapter: claudecode.Adapter{},
		PolicyPath: policyFile(h.t, h.policy, nil), Getenv: env, StateDir: h.state})
}

func TestTripwireLocksSession(t *testing.T) {
	h := hookRig{t, sessionPolicy("{tripwire: {}}"), t.TempDir()}
	for i, cmd := range []string{"cat .env", "cat ./.env", "terraform apply"} {
		r := h.run(bash("s1", cmd))
		if r.Verdict.Decision != engine.Deny || r.Verdict.Rule == tripwire.RuleLocked {
			t.Fatalf("call %d: %s by %s", i+1, r.Verdict.Decision, r.Verdict.Rule)
		}
		if locked := strings.Contains(r.Verdict.Reason, "locked this session"); locked != (i == 2) {
			t.Fatalf("call %d: reason %q", i+1, r.Verdict.Reason)
		}
	}
	// Locked: even a harmless call is denied, with exit 2
	r := h.run(bash("s1", "ls"))
	assertDenied(t, r, tripwire.RuleLocked)
	if !strings.Contains(r.Verdict.Reason, "3 denied tool calls") || !strings.Contains(r.Verdict.Reason, brand.Name+" unlock") {
		t.Errorf("locked reason: %q", r.Verdict.Reason)
	}
	// Another session is not affected
	if r := h.run(bash("s2", "ls")); r.Exit != 0 {
		t.Fatalf("another session: exit %d, %s by %s", r.Exit, r.Verdict.Decision, r.Verdict.Rule)
	}
	// Unlocking restores the session
	if _, err := (tripwire.Store{Dir: h.state}).Unlock("claude-code", "s1"); err != nil {
		t.Fatal(err)
	}
	if r := h.run(bash("s1", "ls")); r.Exit != 0 {
		t.Fatalf("after unlock: exit %d, %s by %s", r.Exit, r.Verdict.Decision, r.Verdict.Rule)
	}
}

// Off unless the policy configures it: no lock, and no state needed
func TestTripwireOffByDefault(t *testing.T) {
	for _, session := range []string{"{}", "{briefing: {}}"} {
		h := hookRig{t, sessionPolicy(session), ""}
		for i := range 5 {
			assertDenied(t, h.run(bash("s1", "cat .env")), "files.deny[0]")
			if i == 4 {
				if r := h.run(bash("s1", "ls")); r.Exit != 0 {
					t.Fatalf("session %s: harmless call after 5 denials: exit %d, %s by %s", session, r.Exit, r.Verdict.Decision, r.Verdict.Rule)
				}
			}
		}
	}
}

func TestTripwireSettings(t *testing.T) {
	t.Run("off", func(t *testing.T) {
		h := hookRig{t, sessionPolicy("{tripwire: {enabled: false}}"), t.TempDir()}
		for range 5 {
			h.run(bash("s", "cat .env"))
		}
		if r := h.run(bash("s", "ls")); r.Exit != 0 {
			t.Fatalf("tripwire off: %s by %s", r.Verdict.Decision, r.Verdict.Rule)
		}
		entries, _ := os.ReadDir(h.state)
		if len(entries) != 0 {
			t.Errorf("tripwire off wrote state: %v", entries)
		}
	})
	t.Run("off needs no state directory", func(t *testing.T) {
		h := hookRig{t, sessionPolicy("{tripwire: {enabled: false}}"), ""}
		if r := h.run(bash("s", "ls")); r.Exit != 0 {
			t.Fatalf("%s by %s", r.Verdict.Decision, r.Verdict.Rule)
		}
	})
	t.Run("limit", func(t *testing.T) {
		h := hookRig{t, sessionPolicy("{tripwire: {maxDenials: 1}}"), t.TempDir()}
		h.run(bash("s", "cat .env"))
		assertDenied(t, h.run(bash("s", "ls")), tripwire.RuleLocked)
	})
	t.Run("a secret counts", func(t *testing.T) {
		h := hookRig{t, sessionPolicy("{tripwire: {maxDenials: 1}}"), t.TempDir()}
		token, _ := secretstest.Fake("github-pat")
		assertDenied(t, h.run(bash("s", "export GH_TOKEN="+token)), engine.RuleSecretsPrefix+"github-pat")
		assertDenied(t, h.run(bash("s", "ls")), tripwire.RuleLocked)
	})
}

// Only the policy's own denials count: asks, allowed calls and CyberBoar's
// limits (an unclassified tool) are no sign of an agent probing the rules
func TestTripwireCountsPolicyDenialsOnly(t *testing.T) {
	h := hookRig{t, sessionPolicy("{tripwire: {maxDenials: 2}}"), t.TempDir()}
	unclassified := `{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"SomeNewTool","cwd":"/work/repo","tool_input":{}}`
	for range 3 {
		h.run(bash("s", "cat infra/terraform.tfstate")) // ask
		h.run(bash("s", "ls"))
		if r := h.run(unclassified); r.Verdict.Rule != adapters.RuleUnclassifiedTool {
			t.Fatalf("unclassified tool: %s by %s", r.Verdict.Decision, r.Verdict.Rule)
		}
	}
	h.run(bash("s", "cat .env"))
	if r := h.run(bash("s", "ls")); r.Exit != 0 {
		t.Fatalf("one policy denial must not lock at limit 2: %s by %s", r.Verdict.Decision, r.Verdict.Rule)
	}
}

// The tripwire is fail-closed: without readable state, nothing runs
func TestTripwireStateErrorsDeny(t *testing.T) {
	h := hookRig{t, sessionPolicy("{tripwire: {}}"), ""}
	assertDenied(t, h.run(bash("s", "ls")), hook.RuleTripwireState)

	// Without a session ID there is no session to count denials for
	h.state = t.TempDir()
	if r := h.run(bash("", "ls")); r.Verdict.Rule != hook.RuleTripwireState || !strings.Contains(r.Verdict.Reason, "session ID") {
		t.Fatalf("no session ID: %s by %s (%s)", r.Verdict.Decision, r.Verdict.Rule, r.Verdict.Reason)
	}
	if r := (hookRig{t, sessionPolicy("{}"), ""}).run(bash("", "ls")); r.Exit != 0 {
		t.Fatalf("no session ID, tripwire off: %s by %s", r.Verdict.Decision, r.Verdict.Rule)
	}

	h.state = t.TempDir()
	h.run(bash("s", "cat .env"))
	files, _ := filepath.Glob(filepath.Join(h.state, "sessions", "*.json"))
	if len(files) != 1 {
		t.Fatalf("state files: %v", files)
	}
	// A state file holds at most 64 KiB, so a larger one is refused even when it is valid JSON
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files[0], append(data, strings.Repeat(" ", 64<<10+1-len(data))...), 0o600); err != nil {
		t.Fatal(err)
	}
	assertDenied(t, h.run(bash("s", "ls")), hook.RuleTripwireState)
	os.WriteFile(files[0], []byte("{corrupt"), 0o600)
	assertDenied(t, h.run(bash("s", "ls")), hook.RuleTripwireState)

	// State that can't be written turns a denial into an error denial
	// A dangling symlink where the sessions directory goes reads as a session
	// with no state yet, and no user, root included, can create the directory through it
	h.state = t.TempDir()
	if err := os.Symlink(filepath.Join(h.state, "missing"), filepath.Join(h.state, "sessions")); err != nil {
		t.Fatal(err)
	}
	assertDenied(t, h.run(bash("s", "cat .env")), hook.RuleTripwireState)
}

// The agent can't reach the state to undo a lock
func TestStateDirIsProtected(t *testing.T) {
	h := hookRig{t, sessionPolicy("{tripwire: {maxDenials: 1}}"), t.TempDir()}
	r := h.run(bash("s", "rm -rf "+h.state))
	if r.Verdict.Rule != engine.RuleSelf {
		t.Fatalf("rm -rf of the state: %s by %s", r.Verdict.Decision, r.Verdict.Rule)
	}
	// That attempt counted: the session is locked now
	assertDenied(t, h.run(bash("s", "ls")), tripwire.RuleLocked)

	h = hookRig{t, sessionPolicy("{tripwire: {enabled: false}}"), t.TempDir()}
	read := fmt.Sprintf(`{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Read","cwd":"/work/repo","tool_input":{"file_path":%q}}`,
		filepath.Join(h.state, "sessions", "x.json"))
	assertDenied(t, h.run(read), engine.RuleSelf)
}

// Parallel tool calls must not lose denials
func TestTripwireConcurrentCalls(t *testing.T) {
	h := hookRig{t, sessionPolicy("{tripwire: {maxDenials: 10}}"), t.TempDir()}
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.run(bash("s", "cat .env"))
		}()
	}
	wg.Wait()
	assertDenied(t, h.run(bash("s", "ls")), tripwire.RuleLocked)
}
