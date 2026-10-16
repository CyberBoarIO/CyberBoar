package hook

import (
	"context"
	"fmt"
	"os"
	"testing"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/adapters/claudecode"
	"cyberboar.dev/cyberboar/internal/engine"
	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/pkg/audit"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// On Windows every action is checked with Windows path semantics, whatever
// the adapter set. This calls decide rather than Run: on a host that isn't
// Windows, Run refuses every action, because the policy file is that host's
// path and Windows semantics refuse it as a guarded path.
func TestWindowsPaths(t *testing.T) {
	data, err := os.ReadFile("../../examples/baseline.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Load(data)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := engine.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	cc := claudecode.Adapter{}
	winEnv := func(k string) string {
		return map[string]string{"CLAUDE_PROJECT_DIR": `C:\work\repo`, "HOME": `C:\Users\dev`}[k]
	}
	state := `C:\Users\dev\AppData\Local\` + brand.Name
	decideWith := func(a adapters.Adapter, tool, input string) engine.Verdict {
		t.Helper()
		in := fmt.Sprintf(`{"hook_event_name":"PreToolUse","tool_name":%q,"cwd":"C:\\work\\repo","tool_input":%s}`, tool, input)
		call, err := a.Parse([]byte(in), winEnv)
		if err != nil {
			t.Fatal(err)
		}
		return decide(context.Background(), compiled, call, []string{state}, nil, true, &audit.Event{})
	}
	assertRule := func(v engine.Verdict, rule string) {
		t.Helper()
		if v.Decision != engine.Deny || v.Rule != rule {
			t.Errorf("want deny by %s, got %s by %s (%s)", rule, v.Decision, v.Rule, v.Reason)
		}
	}
	// The adapter still reads its environment as on this OS, so the settings
	// files it guards are POSIX paths, which Windows semantics refuse.
	assertRule(decideWith(cc, "Read", `{"file_path":"C:\\work\\repo\\README.md"}`), engine.RuleInvalidAction)
	check := func(tool, input string) engine.Verdict { return decideWith(unguarded{cc}, tool, input) }
	if v := check("Read", `{"file_path":"C:\\work\\repo\\README.md"}`); v.Decision != engine.Allow {
		t.Errorf("README.md: %+v", v)
	}
	assertRule(check("Read", `{"file_path":"C:\\work\\repo\\.env."}`), "files.deny[0]")
	assertRule(check("Read", `{"file_path":"\\\\localhost\\c$\\x"}`), engine.RuleWindowsPath)
	assertRule(check("Bash", `{"command":"cat /c/work/repo/.ENV"}`), "files.deny[0]")
	assertRule(check("Read", `{"file_path":"C:\\Users\\dev\\AppData\\Local\\`+brand.Name+`\\x"}`), engine.RuleSelf)
}

// unguarded drops the guarded paths an adapter adds.
type unguarded struct{ adapters.Adapter }

func (u unguarded) Parse(data []byte, getenv func(string) string) (*adapters.Call, error) {
	c, err := u.Adapter.Parse(data, getenv)
	if c != nil {
		for i := range c.Actions {
			c.Actions[i].Guarded = nil
		}
	}
	return c, err
}
