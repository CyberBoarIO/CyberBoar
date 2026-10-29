// Package cmdpattern parses command rule patterns such as "git push" or "curl | sh".
//
// A pattern is written in shell syntax: one simple command, or a pipeline of
// simple commands. Each word becomes a Token, a glob against one argv word in
// which unquoted * ? [ are wildcards and "*" also matches "/".
package cmdpattern

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"

	"cyberboar.dev/cyberboar/internal/fold"
)

// Pattern is a parsed command pattern. Stages has one entry for a simple
// command, more for a pipeline ("curl | sh" has two).
type Pattern struct {
	Stages [][]Token
}

// Token matches one argv word.
type Token struct {
	glob string // path.Match syntax, with '/' mapped to sep
	meta bool   // glob contains wildcards
}

// sep stands in for '/' so path.Match's '*' also matches across slashes.
// Command words can't contain NUL, so it never collides.
const sep = "\x00"

// Parse parses a pattern. Errors are phrased for a policy author.
func Parse(s string) (*Pattern, error) {
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(s), "")
	if err != nil {
		return nil, fmt.Errorf("not valid shell syntax: %v", err)
	}
	if len(f.Stmts) != 1 {
		return nil, errors.New("must be exactly one command or pipeline (no ;, && or newlines)")
	}
	var p Pattern
	if err := p.addStages(f.Stmts[0]); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Pattern) addStages(st *syntax.Stmt) error {
	if len(st.Redirs) > 0 || st.Negated || st.Background || st.Coprocess || st.Disown {
		return errors.New("redirections, !, & and similar are not allowed")
	}
	switch c := st.Cmd.(type) {
	case *syntax.BinaryCmd:
		if c.Op != syntax.Pipe && c.Op != syntax.PipeAll {
			return fmt.Errorf("%s is not allowed; use | or one command", c.Op)
		}
		if err := p.addStages(c.X); err != nil {
			return err
		}
		return p.addStages(c.Y)
	case *syntax.CallExpr:
		if len(c.Assigns) > 0 {
			return errors.New("variable assignments are not allowed")
		}
		var toks []Token
		for i, w := range c.Args {
			t, err := wordToken(w)
			if err != nil {
				return fmt.Errorf("word %d: %v", i+1, err)
			}
			toks = append(toks, t)
		}
		if strings.Contains(toks[0].glob, sep) {
			return errors.New("name the command without a path; paths are stripped before matching")
		}
		p.Stages = append(p.Stages, toks)
		return nil
	default:
		return errors.New("only simple commands and | pipelines are allowed")
	}
}

// wordToken returns the Token for one word of a pattern.
// Quoted text matches literally, and unquoted * ? [ stay wildcards.
func wordToken(w *syntax.Word) (Token, error) {
	// The shell expands {a,b} into two words before the command runs, so as
	// a single glob it would never match
	if syntax.SplitBraces(w) {
		return Token{}, errors.New("brace expansion is not supported; write a rule for each alternative, or quote the braces to match them literally")
	}
	var b strings.Builder
	meta := false
	for _, part := range w.Parts {
		switch pt := part.(type) {
		case *syntax.Lit:
			// In unquoted text, wildcards stay wildcards, and backslash escapes
			// mean the same to path.Match as to the shell
			b.WriteString(pt.Value)
			meta = meta || strings.ContainsAny(pt.Value, "*?[")
		case *syntax.SglQuoted:
			if pt.Dollar {
				return Token{}, errors.New("$'...' quoting is not supported")
			}
			b.WriteString(quoteMeta(pt.Value))
		case *syntax.DblQuoted:
			for _, in := range pt.Parts {
				_, ok := in.(*syntax.Lit)
				if !ok || pt.Dollar {
					return Token{}, errors.New("expansions are not allowed")
				}
			}
			// Read shell escapes before quoting glob metacharacters. The
			// validation above excludes all run-time expansions
			value, err := expand.Literal(&expand.Config{}, &syntax.Word{Parts: []syntax.WordPart{pt}})
			if err != nil {
				return Token{}, fmt.Errorf("invalid double-quoted word: %w", err)
			}
			b.WriteString(quoteMeta(value))
		default:
			return Token{}, errors.New("expansions ($VAR, $(...), globs like @(...)) are not allowed")
		}
	}
	glob := strings.ReplaceAll(b.String(), "/", sep)
	if _, err := path.Match(glob, ""); err != nil {
		return Token{}, fmt.Errorf("malformed glob %q", w.Lit())
	}
	return Token{glob: glob, meta: meta}, nil
}

// quoteMeta escapes the glob wildcards in s, so that s matches itself.
func quoteMeta(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`*?[\`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Match reports whether the literal word matches.
// With folded, a match after folding both (which ignores case) also counts.
func (t Token) Match(word string, folded bool) bool {
	word = strings.ReplaceAll(word, "/", sep)
	return globMatch(t.glob, word, folded)
}

// MayMatch reports whether some word of the given shape could match. A shape
// is a glob over the possible values of a word only known at run time: "*"
// for a variable, "*.go" for an unquoted glob. With folded, a match after
// folding both also counts.
func (t Token) MayMatch(shape string, folded bool) bool {
	if t.meta {
		return true // assume two globs can match the same word rather than intersect them
	}
	return globMatch(strings.ReplaceAll(shape, "/", sep), unquote(t.glob), folded)
}

// globMatch reports whether glob matches s as written or, with folded, after
// folding both. Folding a bracket expression can change what it holds ([A-z]
// becomes [a-z], [^e] then also excludes E), so the folded form only adds
// matches to the written one. An error counts as a match: for a deny rule
// that is the stricter answer, and for an ask rule it can ask where
// allow-listed posture would deny, which leaves the call to the user.
// Parse has checked a token's own glob, so only a shape from a command line, or a
// glob that folding has changed, can cause one.
func globMatch(glob, s string, folded bool) bool {
	ok, err := path.Match(glob, s)
	if err == nil && !ok && folded {
		ok, err = path.Match(fold.String(glob), fold.String(s))
	}
	return ok || err != nil
}

// unquote removes the backslash escapes of a wildcard-free glob.
func unquote(glob string) string {
	var b strings.Builder
	esc := false
	for _, r := range glob {
		if r == '\\' && !esc {
			esc = true
			continue
		}
		esc = false
		b.WriteRune(r)
	}
	return b.String()
}
