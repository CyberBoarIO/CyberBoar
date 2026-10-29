package corpustest

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/adapters/edits"
	"cyberboar.dev/cyberboar/internal/engine"
	"cyberboar.dev/cyberboar/internal/policy"
)

// Run builds the file's fixture and executes every case in f as a subtest.
func Run(t *testing.T, f *File) {
	t.Helper()
	root, err := f.BuildFixture()
	if root != "" {
		t.Cleanup(func() { os.RemoveAll(root) })
	}
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			src, err := f.PolicyBytes(c.Policy, root)
			if err != nil {
				t.Fatalf("policy %q: %v", c.Policy, err)
			}
			pol, err := policy.Load(src)
			checkLoad(t, c.Expect, err)
			if c.Action == nil {
				return
			}

			// A policy that failed to load leaves compiled nil; the engine must deny.
			var compiled *engine.Compiled
			if err == nil {
				if compiled, err = engine.Compile(pol); err != nil {
					t.Fatalf("compile: %v", err)
				}
			}
			a, err := f.Action(c, root)
			if err != nil {
				t.Fatal(err)
			}
			got := engine.Evaluate(context.Background(), compiled, a.engineAction())
			checkVerdict(t, c.Expect, got)
		})
	}
}

// engineAction returns the engine.Action a corpus action stands for. Edits,
// insertions and patches each give the content the tools would have written
// and the rewrite the engine checks it against.
func (a *Action) engineAction() engine.Action {
	content, rewrite := a.Content, engine.Rewrite(nil)
	rewriteMoves := false
	switch {
	case len(a.Edits) > 0:
		var es []edits.Replace
		for _, e := range a.Edits {
			es = append(es, edits.Replace{Old: e.Old, New: e.New, All: e.All})
		}
		content, rewrite = adapters.EditText(es), edits.Strings(es)
	case a.Insert != nil:
		content, rewrite = a.Insert.Text, edits.Insert(a.Insert.Line, a.Insert.Text)
	case a.Patch != "":
		content = adapters.PatchText(a.Patch)
		rewrites, moves, err := edits.PatchWithMoves(a.Patch)
		rewrite = rewrites[a.Path]
		rewriteMoves = moves[a.Path]
		if err != nil {
			rewrite = func(string, bool) ([]string, error) { return nil, err }
		}
	}
	return engine.Action{
		Tool:          engine.Tool(a.Tool),
		Command:       a.Command,
		Path:          a.Path,
		Content:       content,
		Rewrite:       rewrite,
		RewriteMoves:  rewriteMoves,
		MCP:           engine.MCPCall{Server: a.MCP.Server, Tool: a.MCP.Tool, Names: mcpNames(a.MCP.Names)},
		Cwd:           a.Cwd,
		CwdUnknown:    a.CwdUnknown,
		ShellPersists: a.ShellPersists,
		Shell:         a.Shell,
		CDPath:        a.CDPath,
		Home:          a.Home,
		Workspaces:    a.Workspaces,
		Protected:     a.Protected,
		Guarded:       a.Guarded,
		Platform:      a.Platform,
		Drives:        a.Drives,
		Mounts:        a.Mounts,
	}
}

func checkLoad(t *testing.T, want Expect, err error) {
	t.Helper()
	if want.LoadError == "" {
		if err != nil {
			t.Fatalf("policy should load, got: %v", err)
		}
		return
	}
	var perr *policy.Error
	if !errors.As(err, &perr) {
		t.Fatalf("want load error %q, got: %v", want.LoadError, err)
	}
	t.Log(perr)
	if string(perr.Code) != want.LoadError {
		t.Errorf("want load error code %q, got %q (%v)", want.LoadError, perr.Code, perr)
	}
	if want.ErrorPath != nil && perr.Path != *want.ErrorPath {
		t.Errorf("want error path %q, got %q (%v)", *want.ErrorPath, perr.Path, perr)
	}
}

func checkVerdict(t *testing.T, want Expect, got engine.Verdict) {
	t.Helper()
	t.Logf("verdict: %s by %s: %s", got.Decision, got.Rule, got.Reason)
	if string(got.Decision) != want.Decision {
		t.Errorf("want decision %q, got %q (rule %s: %s)", want.Decision, got.Decision, got.Rule, got.Reason)
	}
	if want.Rule != "" && got.Rule != want.Rule {
		t.Errorf("want rule %q, got %q (%s)", want.Rule, got.Rule, got.Reason)
	}
	if !strings.Contains(got.Reason, want.ReasonContains) {
		t.Errorf("want reason containing %q, got %q", want.ReasonContains, got.Reason)
	}
}

// mcpNames reads a corpus action's mcp.names.
func mcpNames(s string) engine.MCPNames {
	switch s {
	case "opencode":
		return engine.NamesOpencode
	case "copilot":
		return engine.NamesCopilot
	case "codex":
		return engine.NamesCodex
	case "claude-code":
		return engine.NamesClaudeCode
	case "vscode":
		return engine.NamesVSCode
	}
	return engine.NamesAsConfigured
}
