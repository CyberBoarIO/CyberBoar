package cursor

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/engine"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const testdata = "testdata"

// Cursor runs a preToolUse "ask" as allow, so ask must come out as deny, saying why.
func TestRespondAskIsDeny(t *testing.T) {
	out := Adapter{}.Respond(engine.Verdict{Decision: engine.Ask, Reason: "needs confirmation"}, "cyberboar: ")
	var got map[string]string
	if err := json.Unmarshal(out.Stdout, &got); err != nil {
		t.Fatal(err)
	}
	if out.Exit != 0 || got["permission"] != "deny" || !strings.Contains(got["agent_message"], "can't ask") {
		t.Errorf("ask: exit %d, %v", out.Exit, got)
	}
	if out := (Adapter{}).Respond(engine.Verdict{Decision: engine.Allow}, ""); string(out.Stdout) != "{}\n" || out.Exit != 0 {
		t.Errorf("allow: %+v", out)
	}
}

func TestPathKeyNames(t *testing.T) {
	for key, want := range map[string]bool{
		"file_path": true, "path": true, "target_file": true, "target_directory": true, "paths": true, "filePath": true, "dir": true,
		"cwd": false, "working_directory": false, "workdir": false, "contents": false, "file_text": false, "old_string": false,
		"pattern": false, "glob": false, "query": false, "command": false, "limit": false,
	} {
		if got := pathKey(key); got != want {
			t.Errorf("pathKey(%q) = %v", key, got)
		}
	}
}

func TestHooksGolden(t *testing.T) {
	user := FragmentOptions{Command: "/usr/local/bin/cyberboar", Policy: "/etc/cyberboar/policy.yaml",
		Audit: "/var/log/cyberboar/audit.jsonl", PubKey: "/etc/cyberboar/policy.pub", Deadline: "5s", Briefing: true}
	// A user's own hooks stay, an earlier CyberBoar entry is replaced, and numbers keep their form
	existing := `{"version": 1, "hooks": {
  "afterFileEdit": [{"command": "./format.sh"}],
  "beforeShellExecution": [{"command": "./audit.sh", "timeout": 2.5},
    {"command": "'/old/cyberboar' 'hook' '-agent' 'cursor' '-policy' '/old.yaml' '-deadline' '5s'", "timeout": 15, "failClosed": true}],
  "sessionStart": [{"command": "'/old/cyberboar' 'brief' '-agent' 'cursor' '-policy' '/old.yaml'"}]}}`
	for _, tc := range []struct {
		name, existing string
		o              FragmentOptions
	}{
		{"managed-hooks.json", "", user},
		{"project-hooks.json", "", FragmentOptions{Command: "cyberboar", Policy: ".cyberboar/policy.yaml", Deadline: "5s"}},
		{"merged-hooks.json", existing, user},
	} {
		out, err := MergeHooks([]byte(tc.existing), tc.o)
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
		again, err := MergeHooks(out, tc.o)
		if err != nil || string(again) != string(out) {
			t.Errorf("%s: applying twice changes the file: %v\n%s", tc.name, err, again)
		}
	}
}

func TestMergeHooksRefuses(t *testing.T) {
	o := FragmentOptions{Command: "cyberboar", Policy: "p.yaml", Deadline: "5s"}
	for name, existing := range map[string]string{
		"not JSON":          "hooks:",
		"a list":            "[]",
		"other version":     `{"version": 2, "hooks": {}}`,
		"hooks not object":  `{"version": 1, "hooks": []}`,
		"event not a list":  `{"version": 1, "hooks": {"preToolUse": {}}}`,
		"trailing document": `{"version": 1} {}`,
	} {
		if _, err := MergeHooks([]byte(existing), o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Cursor drops a whole hooks.json whose commands hold a URL
	o.Audit = "https://example.test/audit"
	if _, err := MergeHooks(nil, o); err == nil || !strings.Contains(err.Error(), "://") {
		t.Errorf("URL in the command: %v", err)
	}
}

func TestSessionStartOutput(t *testing.T) {
	if out := (Adapter{}).SessionStartOutput(""); out != nil {
		t.Errorf("empty text: %q", out)
	}
	if out := string(Adapter{}.SessionStartOutput("rules")); out != "{\"additional_context\":\"rules\"}\n" {
		t.Errorf("got %q", out)
	}
}

// Every input captured from a real Cursor run maps cleanly, and the agent
// shell's commands are checked as running in a persistent shell whose
// directory the input doesn't give.
func TestCapturedInputs(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(testdata, "captured*.jsonl"))
	if len(files) == 0 {
		t.Fatal("no captured inputs")
	}
	root := filepath.ToSlash(t.TempDir())
	env := Env{ProjectDir: root + "/proj", Home: root + "/home", Shell: "/bin/bash"}
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			line = strings.ReplaceAll(line, "{{root}}", root)
			if strings.Contains(line, `"hook_event_name":"sessionStart"`) {
				continue // the briefing command reads it
			}
			in, err := ParseInput([]byte(line))
			if err != nil {
				t.Errorf("%s:%d: %v", filepath.Base(name), i+1, err)
				continue
			}
			actions, err := Actions(in, env)
			if err != nil || len(actions) == 0 {
				t.Errorf("%s:%d: %s %s: %d actions, %v", filepath.Base(name), i+1, in.Event, in.ToolName, len(actions), err)
			}
			for _, a := range actions {
				if a.Tool == engine.ToolShell && (!a.ShellPersists || in.Cwd == "" && !a.CwdUnknown) {
					t.Errorf("%s:%d: shell action %+v", filepath.Base(name), i+1, a)
				}
			}
		}
	}
}
