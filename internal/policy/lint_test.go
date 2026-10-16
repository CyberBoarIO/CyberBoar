package policy

import (
	"strings"
	"testing"
)

func TestLintExactDuplicatesAndConflicts(t *testing.T) {
	p := &Policy{}
	p.Spec.Files.Deny = []string{"**/.env*", "**/.env*"}
	p.Spec.MCP.Allow = []string{"github", "github"}
	p.Spec.MCP.Deny = []string{"github"}
	p.Spec.Commands.Allow = []string{"git push"}
	p.Spec.Commands.Ask = []string{"git push"}

	got := Lint(p)
	if len(got) != 4 {
		t.Fatalf("got %d warnings: %#v", len(got), got)
	}
	wantPaths := []string{
		"spec.files.deny[1]",
		"spec.commands.ask[0]",
		"spec.mcp.allow[1]",
		"spec.mcp.deny[0]",
	}
	for i, want := range wantPaths {
		if got[i].Path != want {
			t.Errorf("warning %d: path %q, want %q", i, got[i].Path, want)
		}
	}
	if !strings.Contains(got[3].Message, "deny takes precedence") {
		t.Errorf("conflict warning missing precedence: %q", got[3].Message)
	}
}

func TestLintConservative(t *testing.T) {
	p := &Policy{}
	p.Spec.MCP.Allow = []string{"github/*"}
	p.Spec.MCP.Deny = []string{"github/delete"}
	p.Spec.Files.Allow = []string{"docs/**"}
	p.Spec.Files.Deny = []string{"docs/secrets/**"}
	if got := Lint(p); len(got) != 0 {
		t.Fatalf("overlapping but nonidentical patterns must not warn: %#v", got)
	}
	if got := Lint(nil); len(got) != 0 {
		t.Fatalf("nil policy: %#v", got)
	}
}
