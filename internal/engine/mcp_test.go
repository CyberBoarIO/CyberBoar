package engine

import (
	"context"
	"path"
	"strings"
	"testing"
	"unicode/utf16"

	"cyberboar.dev/cyberboar/internal/policy"
)

func TestOpencodeGlob(t *testing.T) {
	for in, want := range map[string]string{
		"write.file":   "write_file",
		"write_file":   "write_file",
		"a b":          "a_b",
		"é":            "_",
		"😀x":           "__x",
		`a\.b`:         "a_b",
		`a\*b`:         "a_b",
		`\a`:           `\a`,
		"rm*":          "rm*",
		"get.?":        "get_?*",
		"[a-z]x":       "[a-z]x",
		`[a-z0-9_\-]x`: `[a-z0-9_\-]x`,
		`[\-a]x`:       `[\-a]x`,
		"[A-z]x":       "*x",
		`[\A-z]x`:      "*x",
		"[.x]y":        "*y",
		"[^e]xport":    "*xport",
		"[0-Z]":        "*",
		"":             "",
	} {
		if got := opencodeGlob(in); got != want {
			t.Errorf("opencodeGlob(%q) = %q, want %q", in, got, want)
		}
	}
}

// A rewritten glob matches the rewritten form of every name the glob matches
// as written, including a Unicode character that becomes two underscores
func TestOpencodeGlobCoversRewrittenNames(t *testing.T) {
	rewrite := func(s string) string {
		var b strings.Builder
		for _, r := range s {
			switch {
			case nameChar(r):
				b.WriteRune(r)
			case utf16.RuneLen(r) == 2:
				b.WriteString("__")
			default:
				b.WriteByte('_')
			}
		}
		return b.String()
	}
	globs := []string{
		"write.file", "write.*", "*.file", "a?b", `a\.b`, "[a-z].x", "[A-z]x", "[^a]x",
		`[.\-]x`, "[0-9a-f]*", "*", "x[_.]y", "é*", "😀",
	}
	var names []string
	for _, a := range []string{"", "a", "x", "_", ".", "-", "é", "😀", "Z", "["} {
		for _, b := range []string{"", "b", "x", ".", "_", "file", "é"} {
			for _, c := range []string{"", "write", "w", "a", "0f"} {
				names = append(names, c+a+b, a+c+b, a+b+c, c+"."+a+b)
			}
		}
	}
	for _, g := range globs {
		rg := opencodeGlob(g)
		if _, err := path.Match(rg, ""); err != nil {
			t.Fatalf("opencodeGlob(%q) = %q is not a valid glob", g, rg)
		}
		for _, n := range names {
			if ok, _ := path.Match(g, n); !ok {
				continue
			}
			if ok, _ := path.Match(rg, rewrite(n)); !ok {
				t.Errorf("%q matches %q, but %q doesn't match %q", g, n, rg, rewrite(n))
			}
		}
	}
}

func TestCopilotGlob(t *testing.T) {
	for in, want := range map[string]string{
		"github":     "github",
		"fs.srv":     "fs*srv",
		"write.file": "write*file",
		"My Srv.é😀":  "My*Srv**",
		"é1":         "*",
		"dash-ed":    "dash-ed",
		"under_s":    "under_s",
		"delete_*":   "delete_*",
		`a\.b`:       "a*b",
		`\a`:         `\a`,
		"[a-z]x":     "[a-z]x",
		"[.x]y":      "*",
		"x[^a]":      "*",
		"get.?":      "get*?",
		"":           "",
	} {
		if got := copilotGlob(in, false); got != want {
			t.Errorf("copilotGlob(%q, false) = %q, want %q", in, got, want)
		}
	}
}

// A glob rewritten for Copilot matches the name Copilot makes of every name
// the glob matches as written. copilotName follows Copilot CLI 1.0.97: other
// ASCII punctuation becomes "-", and a part with Unicode is written as punycode,
// here a stand-in with the part's ASCII characters first
func TestCopilotGlobCoversCopilotNames(t *testing.T) {
	copilotName := func(s string) string {
		var parts []string
		for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r < 0x80 && !nameChar(r) }) {
			ascii, other := "", false
			for _, r := range part {
				if r < 0x80 {
					ascii += string(r)
				} else {
					other = true
				}
			}
			if other {
				part = "xn--" + ascii + "-9fa"
			}
			parts = append(parts, part)
		}
		return strings.Join(parts, "-")
	}
	globs := []string{"write.file", "write.*", "*.file", "a b", `a\.b`, "[a-z].x", "fs.srv", "é1", "x.é", "Up.Case", "a?b", "a*b", "a[^x]b", "a[é]b"}
	var names []string
	for _, a := range []string{"", "a", "x", "write", "fs", "Up", "é"} {
		for _, sep := range []string{".", " ", "/", "-", "_", ""} {
			for _, b := range []string{"", "b", "file", "srv", "Case", "1", "é", "x"} {
				names = append(names, a+sep+b)
			}
		}
	}
	for _, g := range globs {
		for _, n := range names {
			if ok, _ := path.Match(g, n); !ok {
				continue
			}
			name := copilotName(n)
			cg := copilotGlob(g, strings.Contains(name, "xn--"))
			if _, err := path.Match(cg, ""); err != nil {
				t.Fatalf("copilotGlob(%q) = %q is not a valid glob", g, cg)
			}
			if ok, _ := path.Match(cg, name); !ok {
				t.Errorf("%q matches %q, but %q doesn't match %q", g, n, cg, copilotName(n))
			}
		}
	}
}

func TestCodexGlob(t *testing.T) {
	for in, want := range map[string]string{
		"github":     "github",
		"github-mcp": "github_mcp",
		"fs.srv":     "fs_srv",
		"write.file": "write_file",
		"é1":         "_1",
		"😀":          "_",
		"delete_*":   "delete_*",
		`a\-b`:       "a_b",
		"[a-z]x":     "[a-z]x",
		`[a\-z]x`:    "*x",
		"[^e]xport":  "*xport",
		"":           "",
	} {
		if got := codexGlob(in); got != want {
			t.Errorf("codexGlob(%q) = %q, want %q", in, got, want)
		}
	}
}

// A glob rewritten for Codex matches Codex's form of every name the glob
// matches as written. codexName is sanitize_responses_api_tool_name from
// codex-rs 0.155: one "_" for each character outside [A-Za-z0-9_]
func TestCodexGlobCoversCodexNames(t *testing.T) {
	codexName := func(s string) string {
		var b strings.Builder
		for _, r := range s {
			if codexChar(r) {
				b.WriteRune(r)
			} else {
				b.WriteByte('_')
			}
		}
		return b.String()
	}
	globs := []string{"github-mcp", "fs.srv", "write.*", "*-file", "a?b", `a\-b`, "[a-z]-x", "[-.]x", "é*", "😀"}
	var names []string
	for _, a := range []string{"", "a", "github", "fs", "write", "é", "😀"} {
		for _, sep := range []string{"-", ".", "_", " ", ""} {
			for _, b := range []string{"", "b", "mcp", "srv", "file", "x", "é"} {
				names = append(names, a+sep+b)
			}
		}
	}
	for _, g := range globs {
		cg := codexGlob(g)
		if _, err := path.Match(cg, ""); err != nil {
			t.Fatalf("codexGlob(%q) = %q is not a valid glob", g, cg)
		}
		for _, n := range names {
			if ok, _ := path.Match(g, n); !ok {
				continue
			}
			if ok, _ := path.Match(cg, codexName(n)); !ok {
				t.Errorf("%q matches %q, but %q doesn't match %q", g, n, cg, codexName(n))
			}
		}
	}
}

func TestCodexHashed(t *testing.T) {
	for name, want := range map[string]bool{
		"write_file_0123456789ab": true, "_0123456789ab": true, "write_file": false,
		"write_file_0123456789AB": false, "x0123456789ab": false, "write_file_0123456789a": false,
	} {
		if got := codexHashed(name); got != want {
			t.Errorf("codexHashed(%q) = %v", name, got)
		}
	}
}

// Deny and ask patterns cover rewritten Unicode names, while allow rules
// still require the spelling reported by the agent
func TestMCPRewrittenUnicodeWildcards(t *testing.T) {
	for _, tc := range []struct {
		name, pattern, server, tool string
		names                       MCPNames
	}{
		{"opencode tool", "fs/?", "fs", "__", NamesOpencode},
		{"opencode tool with literals", "fs/a?b", "fs", "a__b", NamesOpencode},
		{"claude server", "?/write", "__", "write", NamesClaudeCode},
		{"copilot server question", "a?b/read", "xn--ab-bja", "read", NamesCopilot},
		{"copilot server star", "a*b/read", "xn--ab-bja", "read", NamesCopilot},
		{"copilot tool question", "fs/a?b", "fs", "xn--ab-bja", NamesCopilot},
		{"copilot tool star", "fs/a*b", "fs", "xn--ab-bja", NamesCopilot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := Action{Tool: ToolMCP, MCP: MCPCall{Server: tc.server, Tool: tc.tool, Names: tc.names}}
			p := emptyPolicy(policy.DenyListed)
			p.Spec.MCP.Deny = []string{tc.pattern}
			assertDeny(t, Evaluate(context.Background(), mustCompile(t, p), a), "mcp.deny[0]")
			p.Spec.MCP.Deny = nil
			p.Spec.MCP.Ask = []string{tc.pattern}
			if v := Evaluate(context.Background(), mustCompile(t, p), a); v.Decision != Ask || v.Rule != "mcp.ask[0]" {
				t.Errorf("ask pattern: got %s by %s", v.Decision, v.Rule)
			}
			p = emptyPolicy(policy.AllowListed)
			p.Spec.MCP.Allow = []string{tc.pattern}
			assertDeny(t, Evaluate(context.Background(), mustCompile(t, p), a), RulePostureAllowListed)
			p.Spec.MCP.Allow = []string{tc.server + "/" + tc.tool}
			if v := Evaluate(context.Background(), mustCompile(t, p), a); v.Decision != Allow || v.Rule != "mcp.allow[0]" {
				t.Errorf("reported-name allow: got %s by %s", v.Decision, v.Rule)
			}
		})
	}
}

// Widening a punycode server pattern must not widen an ASCII tool pattern
func TestCopilotWildcardKeepsASCIIScope(t *testing.T) {
	for _, server := range []string{"fs", "xn--ab-bja"} {
		p := emptyPolicy(policy.DenyListed)
		p.Spec.MCP.Deny = []string{"*/delete_*"}
		for _, tc := range []struct {
			tool string
			want Decision
		}{
			{"delete_file", Deny},
			{"read_file", Allow},
		} {
			a := Action{Tool: ToolMCP, MCP: MCPCall{Server: server, Tool: tc.tool, Names: NamesCopilot}}
			if v := Evaluate(context.Background(), mustCompile(t, p), a); v.Decision != tc.want {
				t.Errorf("%s/%s: got %s by %s, want %s", server, tc.tool, v.Decision, v.Rule, tc.want)
			}
		}
	}
}

func TestGlobMatchesStart(t *testing.T) {
	for _, tc := range []struct {
		pattern, name string
		want          bool
	}{
		{"write_*", "write_xx", true},
		{"write_*", "read_xx", false},
		{"read_file_all", "read_fi", true},
		{"read_file_all", "read_fx", false},
		{"*_all", "anything", true},
		{"[rw]ead", "re", true},
		{"[^r]ead", "re", false},
		{`\*x`, "*", true},
		{`\*x`, "a", false},
		{"a?c", "ab", true},
		{"", "a", false},
	} {
		got, err := globMatchesStart(tc.pattern, tc.name)
		if err != nil || got != tc.want {
			t.Errorf("globMatchesStart(%q, %q) = %v, %v; want %v", tc.pattern, tc.name, got, err, tc.want)
		}
	}
	if _, err := globMatchesStart("[ab", "a"); err == nil {
		t.Error("an unclosed class is no error")
	}
}

// globMatchesStart finds every name a pattern matches with some ending
func TestGlobMatchesStartCoversEndings(t *testing.T) {
	patterns := []string{"ab*", "a?b", "[ab]c", "[^a]b*", `a\*`, "*b", "a*b*c", "abc", "?", "[a-b]?"}
	alphabet := []string{"", "a", "b", "c", "*"}
	var names []string
	for _, x := range alphabet {
		for _, y := range alphabet {
			names = append(names, x+y)
		}
	}
	for _, p := range patterns {
		for _, name := range names {
			if name == "" {
				continue
			}
			some := false
			for _, e1 := range alphabet {
				for _, e2 := range alphabet {
					if ok, _ := path.Match(p, name+e1+e2); ok {
						some = true
					}
				}
			}
			if got, err := globMatchesStart(p, name); err != nil || some && !got {
				t.Errorf("globMatchesStart(%q, %q) = %v, %v; an ending matches", p, name, got, err)
			}
		}
	}
}
