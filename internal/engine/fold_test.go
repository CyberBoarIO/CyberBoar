package engine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"testing"

	"github.com/bmatcuk/doublestar/v4"

	"cyberboar.dev/cyberboar/internal/engine"
	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// TestFoldingNeverNarrows checks that a deny or ask rule whose pattern matches
// a name as written matches it in the engine too, for bracket expressions
// that case folding changes. File patterns are doublestar globs, MCP and
// command patterns path.Match globs, and each is checked against every
// printable ASCII character and a few letters with unusual case mappings
func TestFoldingNeverNarrows(t *testing.T) {
	classes := []string{
		"[A-z]", "[Z-a]", "[!e]", "[^e]", "[!a-z]", "[^A-Z]", "[a-zA-Z]",
		"[K]", "[!k]", "[ſ]", "[!ß]",
	}
	var runes []rune
	for r := rune(' '); r <= '~'; r++ {
		if r != '/' {
			runes = append(runes, r)
		}
	}
	runes = append(runes, 'K', 'ſ', 'é', 'É', 'ß', 'İ', 'ı')

	const repo = "/work/repo"
	for _, kind := range []string{"deny", "ask"} {
		want := engine.Deny
		if kind == "ask" {
			want = engine.Ask
		}
		for _, class := range classes {
			glob := "x" + class + "y"
			files := compileRule(t, "files", kind, "**/"+glob)
			mcp := compileRule(t, "mcp", kind, glob)
			cmds := compileRule(t, "commands", kind, "probe "+glob)
			for _, r := range runes {
				name := "x" + string(r) + "y"
				if ok, _ := doublestar.Match("**/"+glob, strings.TrimPrefix(repo, "/")+"/"+name); ok {
					a := engine.Action{Tool: engine.ToolRead, Path: name, Cwd: repo, Home: "/home/dev", Workspaces: []string{repo}}
					checkFolded(t, files, a, want, "files."+kind+"[0]")
				}
				if ok, _ := path.Match(glob, name); !ok {
					continue
				}
				a := engine.Action{Tool: engine.ToolMCP, MCP: engine.MCPCall{Server: name, Tool: "t"}}
				checkFolded(t, mcp, a, want, "mcp."+kind+"[0]")
				a = engine.Action{Tool: engine.ToolShell, Command: "probe " + shellQuote(name), Cwd: repo, Home: "/home/dev", Workspaces: []string{repo}}
				checkFolded(t, cmds, a, want, "commands."+kind+"[0]")
			}
		}
	}
}

// compileRule compiles a policy with one rule: pattern in section's kind list
func compileRule(t *testing.T, section, kind, pattern string) *engine.Compiled {
	t.Helper()
	doc, err := json.Marshal(map[string]any{
		"apiVersion": brand.APIVersion,
		"kind":       "Policy",
		"metadata":   map[string]any{"name": "fold"},
		"spec":       map[string]any{section: map[string]any{kind: []string{pattern}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Load(doc)
	if err != nil {
		t.Fatalf("%s.%s %q: %v", section, kind, pattern, err)
	}
	c, err := engine.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func checkFolded(t *testing.T, c *engine.Compiled, a engine.Action, want engine.Decision, rule string) {
	t.Helper()
	v := engine.Evaluate(context.Background(), c, a)
	if v.Decision != want || v.Rule != rule {
		t.Errorf("%s: %s by %s (%s), want %s by %s", describe(a), v.Decision, v.Rule, v.Reason, want, rule)
	}
}

func describe(a engine.Action) string {
	switch a.Tool {
	case engine.ToolMCP:
		return fmt.Sprintf("mcp %q", a.MCP.Server)
	case engine.ToolShell:
		return fmt.Sprintf("shell %q", a.Command)
	default:
		return fmt.Sprintf("%s %q", a.Tool, a.Path)
	}
}

// shellQuote quotes s as one shell word
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
