package shell

import (
	"errors"
	"os/user"
	"path"
	"slices"
	"strings"
	"unicode/utf8"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// Kind says how much is known about an argv element.
type Kind int

const (
	// Lit is exactly one word with a known value.
	Lit Kind = iota
	// One is exactly one word whose value is only known at run time, e.g. "$X".
	One
	// Many is zero or more words only known at run time, e.g. unquoted $X
	// (field splitting) or a glob like *.go.
	Many
)

// Elem is one argv element. For Lit, Text is the value.
// For One and Many, Text is the shape: a glob every possible word matches ("*" if nothing is known).
type Elem struct {
	Kind Kind
	Text string
	// Glob marks an unquoted glob (Many): Text is the pattern, and it expands
	// to existing paths. Otherwise a Many is a run-time value.
	Glob bool
	// Shape is set for a run-time value whose literal parts can be read: a
	// glob over what the word may be before field splitting, its literal
	// parts with each run-time part as "*" ("/proc/*/environ" for
	// /proc/$PPID/environ). The built-in rules check it, since its literal
	// parts can pin it under /proc or /dev.
	Shape string
	// Src is a run-time value's word as written ("$f"), for messages.
	Src string
}

// String returns the element as written in messages: a literal or glob
// shape, or "…" for a value only known at run time.
func (e Elem) String() string {
	if e.Kind == Lit || e.Glob || e.Text != "*" {
		return e.Text // a literal, or a glob shape like *.go
	}
	return "…"
}

// Shown returns the element as written in messages, as String does, but
// shows a value only known at run time as its word ("$f") where known.
func (e Elem) Shown() string {
	if s := e.String(); s != "…" || e.Src == "" {
		return s
	}
	return e.Src
}

// maxSrc bounds Elem.Src, so a long word doesn't flood a message.
const maxSrc = 80

// wordSrc returns w as written, cut to maxSrc bytes.
func wordSrc(w *syntax.Word) string {
	var b strings.Builder
	if err := syntax.NewPrinter().Print(&b, w); err != nil {
		return ""
	}
	s := b.String()
	if len(s) > maxSrc {
		cut := maxSrc
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "…"
	}
	return s
}

// classify reports what a word expands to, without expanding it.
func (a *analyzer) classify(w *syntax.Word) Kind {
	kind := Lit
	glob := false
	raise := func(k Kind) {
		if k > kind {
			kind = k
		}
	}
	if t, ok := tildePrefix(w); ok {
		switch {
		case t == "" && a.homeUnsure:
			raise(One) // HOME may have been changed
		case t != "":
			if _, found := a.userHome(t); !found {
				raise(One) // ~+, ~-, ~N or a user this machine doesn't know
			}
		}
	}
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			glob = glob || hasUnescapedMeta(p.Value)
		case *syntax.SglQuoted:
			if _, ok := ansiC(p, p == w.Parts[len(w.Parts)-1]); !ok {
				raise(One) // shells read the escape differently
			}
		case *syntax.DblQuoted:
			for _, in := range p.Parts {
				switch ip := in.(type) {
				case *syntax.Lit:
				case *syntax.ParamExp:
					switch {
					case a.knownParam(ip, true):
					case ip.Param != nil && (ip.Param.Value == "@" || ip.Index != nil),
						ip.Excl && ip.Names != syntax.NamesPrefix:
						// "$@", "${a[@]}" and "${!prefix@}" expand to any number
						// of words, and so does "${!x}" with x=@
						raise(Many)
					default:
						raise(One)
					}
				default: // command and arithmetic substitution
					raise(One)
				}
			}
		case *syntax.ParamExp:
			if !a.knownParam(p, false) {
				raise(Many) // unquoted: field splitting and globbing
			}
		case *syntax.ProcSubst:
			raise(One) // becomes one /dev/fd/N path
		default: // CmdSubst, ArithmExp, ExtGlob, …
			raise(Many)
		}
	}
	if glob || zshGlobSubst(w.Parts) {
		raise(Many) // zsh's $~NAME and $=NAME expand the value of NAME as a glob or a path
	}
	return kind
}

// knownParam reports a plain $NAME or ${NAME} whose value the engine knows:
// HOME (the action's home directory), or a variable the line set itself
// (vars.go). Unquoted, the value must also come through field splitting and
// globbing as it is.
func (a *analyzer) knownParam(p *syntax.ParamExp, quoted bool) bool {
	if p.Param == nil || p.Excl || p.Length || p.Width || p.IsSet || p.Flags != nil || p.NestedParam != nil ||
		p.Index != nil || len(p.Modifiers) > 0 || p.Slice != nil || p.Repl != nil || p.Names != 0 || p.Exp != nil {
		return false
	}
	if p.Param.Value == "HOME" {
		return !a.homeUnsure
	}
	v, ok := a.vars[p.Param.Value]
	return ok && (quoted || splitSafe(v))
}

func hasUnescapedMeta(s string) bool {
	esc := false
	for _, r := range s {
		switch {
		case esc:
			esc = false
		case r == '\\':
			esc = true
		case r == '*' || r == '?' || r == '[':
			return true
		}
	}
	return false
}

// word turns one shell word into argv elements.
// A literal word with brace expansion becomes several elements.
func (a *analyzer) word(w *syntax.Word) []Elem {
	switch a.classify(w) {
	case One:
		return []Elem{{Kind: One, Text: a.tildeShape(w), Shape: a.shape(w), Src: wordSrc(w)}}
	case Many:
		if !a.hasDynamicPart(w) {
			if f, err := a.fields(w); err == nil && len(f) == 1 {
				return []Elem{{Kind: Many, Text: f[0], Glob: true}} // a glob: its words all match the glob itself
			}
		}
		return []Elem{{Kind: Many, Text: "*", Shape: a.shape(w), Src: wordSrc(w)}}
	}
	f, err := a.fields(w)
	if err != nil {
		return []Elem{{Kind: Many, Text: "*", Src: wordSrc(w)}}
	}
	out := make([]Elem, len(f))
	for i, v := range f {
		out[i] = Elem{Kind: Lit, Text: v}
	}
	return out
}

func (a *analyzer) hasDynamicPart(w *syntax.Word) bool {
	if zshGlobSubst(w.Parts) {
		return true // $~NAME is a value, not the text written
	}
	for i, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.SglQuoted:
			if _, ok := ansiC(p, i == len(w.Parts)-1); !ok {
				return true
			}
		case *syntax.Lit:
		default:
			return true
		}
	}
	return false
}

// fields expands a word that has no run-time parts the way the shell would:
// quote and escape removal, $'…', brace expansion, ~ and $HOME.
// Globs are not expanded (no directory access).
func (a *analyzer) fields(w *syntax.Word) ([]string, error) {
	// ~user: substitute the home the analyzer looked up, instead of letting
	// the expander do its own lookup (or keep it literal if unknown)
	if t, ok := tildePrefix(w); ok && t != "" {
		l := w.Parts[0].(*syntax.Lit)
		rest := strings.TrimPrefix(l.Value, "~"+t)
		var first []syntax.WordPart
		if home, found := a.userHome(t); found {
			first = []syntax.WordPart{&syntax.SglQuoted{Value: home}, &syntax.Lit{Value: rest}}
		} else {
			first = []syntax.WordPart{&syntax.Lit{Value: `\` + l.Value}}
		}
		w = &syntax.Word{Parts: append(first, w.Parts[1:]...)}
	}
	// $'…': decode it here rather than trust the expander, which reads some
	// escapes differently from bash (classify made the rest run-time words).
	var parts []syntax.WordPart
	for i, part := range w.Parts {
		if q, ok := part.(*syntax.SglQuoted); ok && q.Dollar {
			if parts == nil {
				parts = slices.Clone(w.Parts)
			}
			v, ok := ansiC(q, i == len(w.Parts)-1)
			if !ok {
				return nil, errUncertainEscape
			}
			parts[i] = &syntax.SglQuoted{Value: v}
		}
	}
	if parts != nil {
		w = &syntax.Word{Parts: parts}
	}
	return expand.Fields(a.expandCfg, w)
}

var errUncertainEscape = errors.New("an escape in $'…' that shells read differently")

// ansiC returns the value of a single-quoted string, decoding $'…'. ok is
// false when an escape means different things to different shells, versions
// or locales: \x{HH}, \cX, \uHHHH and \UHHHHHHHH (bash 4.2+ reads them, bash
// 3.2 and zsh don't, or not the same way), octal above \377 or with a leading
// 0 and more digits, \x without hex digits, \" and \? and any other escape.
// A NUL (\0, \x0, \x00) ends the string in bash, while zsh keeps it and the
// argument ends there when it is run: the same only if the string ends the
// word (last). What remains is read the same everywhere: \a \b \e \E \f \n
// \r \t \v \\ \', octal \N to \NNN and \xH or \xHH.
func ansiC(q *syntax.SglQuoted, last bool) (string, bool) {
	if !q.Dollar {
		return q.Value, true
	}
	s := q.Value
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i++; i == len(s) {
			return "", false
		}
		switch c := s[i]; c {
		case 'a':
			b.WriteByte('\a')
		case 'b':
			b.WriteByte('\b')
		case 'e', 'E':
			b.WriteByte(0x1b)
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'v':
			b.WriteByte('\v')
		case '\\', '\'':
			b.WriteByte(c)
		case '0':
			if !last || i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '7' {
				return "", false
			}
			return b.String(), true // NUL
		case '1', '2', '3', '4', '5', '6', '7':
			v := int(c - '0')
			for n := 0; n < 2 && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '7'; n++ {
				i++
				v = v*8 + int(s[i]-'0')
			}
			if v > 0xff {
				return "", false
			}
			// #nosec G115 -- v <= 0xff, checked above
			b.WriteByte(byte(v))
		case 'x':
			v, n := 0, 0
			for ; n < 2 && i+1 < len(s) && isHex(s[i+1]); n++ {
				i++
				v = v*16 + hexValue(s[i])
			}
			switch {
			case n == 0:
				return "", false
			case v == 0 && !last:
				return "", false
			case v == 0:
				return b.String(), true // NUL
			}
			b.WriteByte(byte(v))
		default:
			return "", false
		}
	}
	return b.String(), true
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func hexValue(c byte) int {
	switch {
	case c <= '9':
		return int(c - '0')
	case c <= 'F':
		return int(c-'A') + 10
	default:
		return int(c-'a') + 10
	}
}

// tildeShape is the shape of a word whose leading tilde can't be resolved but
// whose rest is literal: "~-/id_rsa" is "*/id_rsa", so rules anchored anywhere
// still match its tail. Anything else is "*".
func (a *analyzer) tildeShape(w *syntax.Word) string {
	if _, ok := tildePrefix(w); !ok || len(w.Parts) != 1 {
		return "*"
	}
	l := w.Parts[0].(*syntax.Lit)
	_, rest, hasSlash := strings.Cut(l.Value, "/")
	if !hasSlash || rest == "" || hasUnescapedMeta(rest) || strings.Contains(rest, `\`) {
		return "*"
	}
	return "*/" + rest
}

// shape returns Elem.Shape for a word with run-time parts: its literal parts
// as the shell reads them, glob-escaped, with "*" for each run-time part. It
// returns "" when they can't be read that way: an unquoted glob or brace
// expansion, an escape shells read differently, or a leading tilde whose
// home is unknown.
func (a *analyzer) shape(w *syntax.Word) string {
	if t, ok := tildePrefix(w); ok {
		if _, found := a.userHome(t); t == "" && a.homeUnsure || t != "" && !found {
			return ""
		}
	}
	var b strings.Builder
	var lit []syntax.WordPart // literal parts not yet written
	flush := func() bool {
		if len(lit) == 0 {
			return true
		}
		if l, ok := lit[0].(*syntax.Lit); ok && b.Len() > 0 && strings.HasPrefix(l.Value, "~") {
			// A tilde after a run-time part is not a tilde prefix
			lit[0] = &syntax.Lit{Value: `\` + l.Value}
		}
		f, err := a.fields(&syntax.Word{Parts: lit})
		if err != nil || len(f) != 1 {
			return false
		}
		b.WriteString(escapeGlob(f[0]))
		lit = nil
		return true
	}
	dynamic := func() bool {
		if !flush() {
			return false
		}
		b.WriteString("*")
		return true
	}
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			if hasUnescapedMeta(p.Value) {
				return ""
			}
			lit = append(lit, p)
		case *syntax.SglQuoted:
			lit = append(lit, p)
		case *syntax.DblQuoted:
			for _, in := range p.Parts {
				pe, isParam := in.(*syntax.ParamExp)
				if _, isLit := in.(*syntax.Lit); isLit || isParam && a.knownParam(pe, true) {
					lit = append(lit, &syntax.DblQuoted{Parts: []syntax.WordPart{in}})
				} else if !dynamic() {
					return ""
				}
			}
		case *syntax.ParamExp:
			if a.knownParam(p, false) {
				lit = append(lit, p)
			} else if !dynamic() {
				return ""
			}
		default:
			if !dynamic() {
				return ""
			}
		}
	}
	if !flush() {
		return ""
	}
	return b.String()
}

// escapeGlob escapes the glob metacharacters in s, so that it matches itself.
func escapeGlob(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`*?[\`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// tildePrefix returns the user name after a leading unquoted ~ ("" for ~ and
// ~/…); ok is false when the word doesn't start with one.
func tildePrefix(w *syntax.Word) (string, bool) {
	if len(w.Parts) == 0 {
		return "", false
	}
	l, ok := w.Parts[0].(*syntax.Lit)
	if !ok || !strings.HasPrefix(l.Value, "~") {
		return "", false
	}
	name, _, _ := strings.Cut(l.Value[1:], "/")
	if strings.ContainsAny(name, `\"'$`) {
		return "", false // not a tilde prefix bash would expand
	}
	if name == "" && len(w.Parts) > 1 && !strings.Contains(l.Value, "/") {
		// "~$X": bash doesn't expand a tilde followed by something non-literal
		return "", false
	}
	return name, true
}

// userHome looks up ~name. +, - and digits are the directory stack, which the
// engine doesn't track.
func (a *analyzer) userHome(name string) (string, bool) {
	// On Windows, Git Bash's idea of another user's home isn't the engine's
	if a.windows || name == "+" || name == "-" || strings.TrimLeft(name, "+-0123456789") == "" {
		return "", false
	}
	return lookupHome(name)
}

// lookupHome finds a user's home directory.
func lookupHome(name string) (string, bool) {
	u, err := user.Lookup(name)
	if err != nil || u.HomeDir == "" {
		return "", false
	}
	return u.HomeDir, true
}

func (a *analyzer) words(ws []*syntax.Word) []Elem {
	var out []Elem
	for _, w := range ws {
		out = append(out, a.word(w)...)
	}
	return out
}

// normalize reduces argv[0] to its base name ("/usr/bin/git" → "git"). On
// Windows either separator counts and .exe and .com are dropped, since
// Windows finds bash.exe for "bash" (BASH.EXE -c runs shell code).
func (a *analyzer) normalize(argv []Elem) []Elem {
	if len(argv) == 0 {
		return argv
	}
	name := argv[0].Text
	switch {
	case a.windows:
		name = winProgram(name)
	case strings.Contains(name, "/"):
		name = path.Base(name)
	}
	if name == argv[0].Text {
		return argv
	}
	out := append([]Elem(nil), argv...)
	out[0].Text = name
	return out
}

// join renders argv as the shell code a wrapper like eval or watch would run
// dynamic is true if any element is only known at run time.
func join(argv []Elem) (text string, dynamic bool) {
	parts := make([]string, len(argv))
	for i, e := range argv {
		if e.Kind != Lit {
			dynamic = true
		}
		parts[i] = e.Text
	}
	return strings.Join(parts, " "), dynamic
}
