package cursor_test

import (
	"encoding/json"
	"errors"
	"testing"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/adapters/cursor"
)

func TestClassified(t *testing.T) {
	for name, want := range map[string]bool{"Shell": true, "Read": true, "Write": true, "Delete": true, "Grep": true, "Task": true,
		"MCP:create_issue": true, "Edit": false, "shell": false} {
		in := &cursor.Input{Event: "preToolUse", WorkspaceRoots: []string{"/work"}, ToolName: name, ToolInput: json.RawMessage(`{}`)}
		_, err := cursor.Actions(in, cursor.Env{})
		e, ok := errors.AsType[*adapters.Error](err)
		if got := !(ok && e.Rule == adapters.RuleUnclassifiedTool); got != want {
			t.Errorf("%s classified = %v (err %v)", name, got, err)
		}
	}
}
