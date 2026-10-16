package cmdpattern

import (
	"strings"
	"testing"
)

func TestParseRejects(t *testing.T) {
	for pat, want := range map[string]string{
		"":                     "exactly one command",
		"git push; ls":         "exactly one command",
		"git push && ls":       "is not allowed",
		"FOO=1 git":            "variable assignments",
		"git push >/dev/null":  "redirections",
		"(git push)":           "only simple commands",
		"/usr/bin/git":         "without a path",
		"echo $HOME":           "expansions",
		`echo "$HOME"`:         "expansions",
		"echo $'x'":            "$'...'",
		"rm -rf {/,~}":         "brace expansion",
		"touch f{1..3}":        "brace expansion",
		"x[":                   "shell syntax",
		`a\`:                   "malformed glob",
		"cat @(a|b)":           "expansions",
		"git push origin +*:*": "",
	} {
		_, err := Parse(pat)
		switch {
		case want == "" && err != nil:
			t.Errorf("Parse(%q): %v", pat, err)
		case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
			t.Errorf("Parse(%q) = %v, want an error containing %q", pat, err, want)
		}
	}
}

func TestParseStages(t *testing.T) {
	p, err := Parse("curl * | sh")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Stages) != 2 || len(p.Stages[0]) != 2 || len(p.Stages[1]) != 1 {
		t.Fatalf("stages = %v", p.Stages)
	}
}

func token(t *testing.T, word string) Token {
	t.Helper()
	p, err := Parse("cmd " + word)
	if err != nil {
		t.Fatal(err)
	}
	return p.Stages[0][1]
}

func TestMatch(t *testing.T) {
	for _, tc := range []struct {
		pat, word string
		folded    bool
		want      bool
	}{
		{"push", "push", false, true},
		{"push", "pull", false, false},
		{"*", "a/b/c", false, true}, // * crosses /
		{"src/*.go", "src/x/y.go", false, true},
		{"'*'", "*", false, true}, // quoted wildcards are literal
		{"'*'", "x", false, false},
		{`"a?"`, "ab", false, false},
		{`\*`, "*", false, true},
		{`\*`, "x", false, false},
		{"'{a,b}'", "{a,b}", false, true}, // quoted braces are literal
		{"Push", "push", false, false},
		{"Push", "push", true, true},
		{"[A-Z]x", "ax", true, true}, // folding only adds matches
		{"[^e]x", "Ex", false, true},
	} {
		if got := token(t, tc.pat).Match(tc.word, tc.folded); got != tc.want {
			t.Errorf("%s.Match(%q, %v) = %v, want %v", tc.pat, tc.word, tc.folded, got, tc.want)
		}
	}
}

func TestMayMatch(t *testing.T) {
	for _, tc := range []struct {
		pat, shape string
		want       bool
	}{
		{"push", "*", true},
		{"push", "p*", true},
		{"push", "x*", false},
		{"main.go", "*.go", true},
		{"main.go", "*.rs", false},
		{"'a*b'", "a*b", true}, // literal star in the token, glob star in the shape
		{"*.go", "x", true},    // two globs are assumed to overlap
		{"push", "[", true},    // a malformed shape errs toward matching
	} {
		if got := token(t, tc.pat).MayMatch(tc.shape, false); got != tc.want {
			t.Errorf("%s.MayMatch(%q) = %v, want %v", tc.pat, tc.shape, got, tc.want)
		}
	}
}

func TestDoubleQuotedEscapes(t *testing.T) {
	for _, tc := range []struct {
		pattern, word string
	}{
		{`"\$TOKEN"`, "$TOKEN"},
		{`"a\"b"`, `a"b`},
		{`"a\\b"`, `a\b`},
		{"\"a\\`b\"", "a`b"},
		{"\"a\\\nb\"", "ab"},
		{`"\q"`, `\q`},
		{`"\*"`, `\*`},
		{`"*?[x]"`, `*?[x]`},
		{`"~"`, "~"},
		{`pre"\${x}"post`, "pre${x}post"},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			tok := token(t, tc.pattern)
			for _, folded := range []bool{false, true} {
				if !tok.Match(tc.word, folded) {
					t.Errorf("does not match %q (folded=%v)", tc.word, folded)
				}
				if tok.Match(tc.word+"other", folded) {
					t.Errorf("also matches a different word (folded=%v)", folded)
				}
				if !tok.MayMatch(quoteMeta(tc.word), folded) {
					t.Errorf("does not cover the matching word's literal shape (folded=%v)", folded)
				}
			}
		})
	}
	if tok := token(t, `pre"\$TOKEN"*`); !tok.Match("pre$TOKENsuffix", false) || tok.Match("preOTHERsuffix", false) {
		t.Error("mixed quoting must retain the unquoted wildcard and literal dollar")
	}
}
