package opencode

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/engine"
)

var update = flag.Bool("update", false, "rewrite golden files")

const testdata = "testdata"

func TestClassificationLoads(t *testing.T) {
	if _, err := classification(); err != nil {
		t.Fatal(err)
	}
}

// Every input captured from a real opencode run maps cleanly: known tool,
// well-formed input.
func TestCapturedInputs(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(testdata, "captured-*.jsonl"))
	if len(files) == 0 {
		t.Fatal("no captured inputs")
	}
	root := filepath.ToSlash(t.TempDir())
	env := Env{Home: "/tmp/e2e/home", UserShell: "/bin/bash"}
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			line = strings.ReplaceAll(line, "{{root}}", root)
			in, err := ParseInput([]byte(line))
			if err != nil {
				t.Errorf("%s:%d: %v", filepath.Base(name), i+1, err)
				continue
			}
			if _, err := Actions(in, env); err != nil {
				t.Errorf("%s:%d: %s: %v", filepath.Base(name), i+1, in.Tool, err)
			}
		}
	}
}

// read lists a directory and reads anything else, so the action depends on
// what the path names on disk.
// A path that doesn't exist is read.
func TestReadListsDirectories(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the adapter's path resolution takes POSIX absolute paths")
	}
	root := filepath.ToSlash(t.TempDir())
	if err := os.Mkdir(root+"/proj", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root+"/proj/README.md", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	env := Env{Home: "/tmp/e2e/home", UserShell: "/bin/bash"}
	for path, want := range map[string]engine.Tool{
		root + "/proj":           engine.ToolList,
		root + "/proj/README.md": engine.ToolRead,
		root + "/proj/missing":   engine.ToolRead,
	} {
		line, err := json.Marshal(map[string]any{"tool": "read", "sessionID": "s", "callID": "c", "args": map[string]string{"filePath": path},
			"directory": root, "worktree": root, "shell": "/bin/bash", "mcpServers": []string{}})
		if err != nil {
			t.Fatal(err)
		}
		in, err := ParseInput(line)
		if err != nil {
			t.Fatal(err)
		}
		acts, err := Actions(in, env)
		if err != nil || len(acts) != 1 || acts[0].Tool != want {
			t.Errorf("read %s: %+v, %v; want %s", path, acts, err, want)
		}
	}
}

// Every tool a captured opencode offers the model is classified, and the
// ones left out on purpose stay out, so a new tool shows up here before it
// reaches a user.
func TestCapturedToolsClassified(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(testdata, "tools-*.json"))
	if len(files) == 0 {
		t.Fatal("no captured tool lists")
	}
	tools, err := classification()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var list struct{ Tools, Denied []string }
		if err := json.Unmarshal(data, &list); err != nil {
			t.Fatal(err)
		}
		for _, tool := range list.Tools {
			if _, ok := tools[tool]; !ok {
				t.Errorf("%s: tool %s is not classified in tools.yaml", filepath.Base(f), tool)
			}
		}
		for _, tool := range list.Denied {
			if _, ok := tools[tool]; ok {
				t.Errorf("%s: tool %s is classified, but is listed as denied on purpose", filepath.Base(f), tool)
			}
		}
	}
}

func TestSanitizeMCPName(t *testing.T) {
	for in, want := range map[string]string{
		"github": "github", "my-srv": "my-srv", "a_b": "a_b", "evil.srv": "evil_srv", "a b/c": "a_b_c",
		"é": "_", "😀x": "__x", "": "",
	} {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMCPActions(t *testing.T) {
	calls := func(name string, servers ...string) []engine.MCPCall {
		var out []engine.MCPCall
		for _, a := range mcpActions(name, servers, engine.Action{}) {
			if a.Tool != engine.ToolMCP || a.MCP.Names != engine.NamesOpencode {
				t.Errorf("%s: action %s, names %v", name, a.Tool, a.MCP.Names)
			}
			out = append(out, engine.MCPCall{Server: a.MCP.Server, Tool: a.MCP.Tool})
		}
		return out
	}
	eq := func(got []engine.MCPCall, want ...engine.MCPCall) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}
	if got := calls("github_create_issue", "github", "gitlab"); !eq(got, engine.MCPCall{Server: "github", Tool: "create_issue"}) {
		t.Errorf("github_create_issue: %+v", got)
	}
	if got := calls("a_b_c", "a", "a_b"); !eq(got, engine.MCPCall{Server: "a", Tool: "b_c"}, engine.MCPCall{Server: "a_b", Tool: "c"}) {
		t.Errorf("a_b_c: %+v", got)
	}
	if got := calls("evil_srv_run", "evil.srv"); !eq(got, engine.MCPCall{Server: "evil.srv", Tool: "run"}) {
		t.Errorf("evil_srv_run: %+v", got)
	}
	for _, name := range []string{"github_", "github", "githubx_y", "x_github_y", "_y"} {
		if got := calls(name, "github"); len(got) != 0 {
			t.Errorf("%s: %+v", name, got)
		}
	}
}

func TestRunShellChoosesShell(t *testing.T) {
	for _, tc := range []struct {
		config, user, want string
		bash               bool
	}{
		{"", "/bin/bash", "/bin/bash", true},
		{"", "/usr/bin/zsh", "/usr/bin/zsh", true},
		{"", "", "bash", true},
		{"", "/usr/bin/fish", "bash", true},
		{"nu", "/usr/bin/pwsh", "bash", true}, // the config's shell is refused: bash, not $SHELL
		{"/bin/sh", "/usr/bin/pwsh", "/bin/sh", true},
		{"pwsh", "/bin/bash", "pwsh", false},
		{"", "/bin/ksh", "/bin/ksh", false},
		{"", `C:\Program Files\PowerShell\7\pwsh.exe`, `C:\Program Files\PowerShell\7\pwsh.exe`, false},
		{"", `C:\Program Files\Git\bin\bash.exe`, `C:\Program Files\Git\bin\bash.exe`, true},
	} {
		got := RunShell(tc.config, tc.user)
		if got != tc.want || bashLike(got) != tc.bash {
			t.Errorf("RunShell(%q, %q) = %q (bash-like %v), want %q (%v)", tc.config, tc.user, got, bashLike(got), tc.want, tc.bash)
		}
	}
}

func TestRespondAnswersShim(t *testing.T) {
	a := Adapter{}
	if out := a.Respond(engine.Verdict{Decision: engine.Allow}, "p: "); out.Exit != 0 || string(out.Stdout) != `{"decision":"none"}`+"\n" || out.Stderr != "" {
		t.Errorf("allow: %+v", out)
	}
	for _, d := range []engine.Decision{engine.Ask, engine.Deny} {
		out := a.Respond(engine.Verdict{Decision: d, Reason: "why"}, "p: ")
		var got map[string]string
		if err := json.Unmarshal(out.Stdout, &got); err != nil || got["decision"] != "deny" || !strings.HasPrefix(got["reason"], "p: why") || len(got) != 2 {
			t.Errorf("%s: %q, %v", d, out.Stdout, err)
		}
		if out.Exit != 2 || out.Stderr != got["reason"]+"\n" {
			t.Errorf("%s: exit %d stderr %q", d, out.Exit, out.Stderr)
		}
		if d == engine.Ask && !strings.Contains(got["reason"], "can't ask") {
			t.Errorf("ask: reason %q doesn't say why it is denied", got["reason"])
		}
	}
}

func TestSessionStartOutput(t *testing.T) {
	if out := (Adapter{}).SessionStartOutput(""); out != nil {
		t.Errorf("empty text: %q", out)
	}
	var got map[string]string
	if err := json.Unmarshal((Adapter{}).SessionStartOutput("hi"), &got); err != nil || len(got) != 1 || got["additionalContext"] != "hi" {
		t.Errorf("got %v, %v", got, err)
	}
}

// Generated plugins are reviewed as diffs of golden files.
func TestShimGolden(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    ShimOptions
	}{
		{"user-plugin.js", ShimOptions{Scope: ScopeUser, Command: "/usr/local/bin/cyberboar", Policy: "/etc/cyberboar/policy.yaml",
			Audit: "/var/log/cyberboar/audit.jsonl", PubKey: "/etc/cyberboar/policy.pub", Deadline: "5s", Briefing: true}},
		{"project-plugin.js", ShimOptions{Scope: ScopeProject, Command: "cyberboar", Policy: ".cyberboar/policy.yaml", Deadline: "5s"}},
	} {
		out, err := Shim(tc.o)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(testdata, "apply", tc.name)
		if *update {
			os.MkdirAll(filepath.Dir(path), 0o755)
			os.WriteFile(path, out, 0o644)
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (run go test -update)", err)
		}
		if string(out) != string(want) {
			t.Errorf("output differs from %s (run go test -update and review the diff):\n%s", tc.name, out)
		}
	}
}

// Paths are baked in as JSON string literals: quotes, newlines, a closing
// comment or a template marker in a path can't change the code.
func TestShimLiterals(t *testing.T) {
	odd := "/opt/x\"y\n*/ @@NAME@@ \u2028`${process.exit(0)}`/cyberboar"
	out, err := Shim(ShimOptions{Scope: ScopeUser, Command: odd, Policy: odd, Deadline: "5s"})
	if err != nil {
		t.Fatal(err)
	}
	var command string
	var args []string
	for line := range strings.SplitSeq(string(out), "\n") {
		if v, ok := strings.CutPrefix(line, "const command = "); ok {
			if err := json.Unmarshal([]byte(strings.TrimSuffix(v, ";")), &command); err != nil {
				t.Fatalf("command literal %s: %v", v, err)
			}
		}
		if v, ok := strings.CutPrefix(line, "const hookArgs = "); ok {
			if err := json.Unmarshal([]byte(strings.TrimSuffix(v, ";")), &args); err != nil {
				t.Fatalf("args literal %s: %v", v, err)
			}
		}
	}
	if command != odd || len(args) < 5 || args[4] != odd {
		t.Errorf("command %q args %q", command, args)
	}
	if bytes.Contains(out, []byte("\u2028")) || strings.Count(string(out), "\n") != strings.Count(shimTemplate, "\n") {
		t.Error("a path added a line terminator to the plugin")
	}
	if _, err := Shim(ShimOptions{Scope: ScopeUser, Policy: "/p", Deadline: "5s"}); err == nil {
		t.Error("no command: no error")
	}
}
