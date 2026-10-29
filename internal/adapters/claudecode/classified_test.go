package claudecode_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/adapters/claudecode"
)

// unclassified reports whether Actions blocks tool as unclassified.
func unclassified(tool string) bool {
	_, err := claudecode.Actions(&claudecode.Input{ToolName: tool, Cwd: "/work", ToolInput: json.RawMessage(`{}`)}, claudecode.Env{})
	var e *adapters.Error
	return errors.As(err, &e) && e.Rule == adapters.RuleUnclassifiedTool
}

// Every tool in a captured Claude Code tool list must be classified, so an
// unclassified tool shows up here before it reaches a user.
func TestCapturedToolsClassified(t *testing.T) {
	files, _ := filepath.Glob("testdata/tools-*.json")
	if len(files) == 0 {
		t.Fatal("no captured tool lists")
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var list struct{ Tools []string }
		if err := json.Unmarshal(data, &list); err != nil {
			t.Fatal(err)
		}
		for _, tool := range list.Tools {
			if unclassified(tool) {
				t.Errorf("%s: tool %s is not classified in tools.yaml", filepath.Base(f), tool)
			}
		}
	}
	for _, tool := range []string{"NoSuchTool", "bash"} {
		if !unclassified(tool) {
			t.Errorf("%s is classified", tool)
		}
	}
}

// Every input captured from a real Claude Code run maps cleanly: known tool, well-formed input.
func TestCapturedInputs(t *testing.T) {
	files, _ := filepath.Glob("testdata/captured-*.jsonl")
	if len(files) == 0 {
		t.Fatal("no captured inputs")
	}
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			line = strings.ReplaceAll(line, "{{root}}", "/work/repo")
			in, err := claudecode.ParseInput([]byte(line))
			if err != nil {
				t.Errorf("%s:%d: %v", filepath.Base(name), i+1, err)
				continue
			}
			if _, err := claudecode.Actions(in, claudecode.Env{ProjectDir: "/work/repo", Home: "/home/dev"}); err != nil {
				t.Errorf("%s:%d: %s: %v", filepath.Base(name), i+1, in.ToolName, err)
			}
		}
	}
}

// Tools later Claude Code releases offer that touch no local file and run no command.
func TestNewerToolsClassified(t *testing.T) {
	for _, tool := range []string{"TaskCreate", "TaskGet", "TaskList", "TaskUpdate", "SendFeedback", "EndConversation"} {
		if unclassified(tool) {
			t.Errorf("%s is not classified", tool)
		}
	}
}
