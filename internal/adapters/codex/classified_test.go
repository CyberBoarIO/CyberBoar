package codex_test

import (
	"encoding/json"
	"errors"
	"testing"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/adapters/codex"
)

func TestClassified(t *testing.T) {
	for name, want := range map[string]bool{"Bash": true, "apply_patch": true, "mcp__x__y": true, "exec": false, "write_stdin": false} {
		_, err := codex.Actions(&codex.Input{ToolName: name, Cwd: "/work", ToolInput: json.RawMessage(`{}`)}, codex.Env{Home: "/home/dev", Shell: "/bin/bash"})
		var e *adapters.Error
		if got := !(errors.As(err, &e) && e.Rule == adapters.RuleUnclassifiedTool); got != want {
			t.Errorf("%s classified = %v (err %v)", name, got, err)
		}
	}
}
