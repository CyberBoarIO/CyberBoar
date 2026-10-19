package shell

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"mvdan.cc/sh/v3/syntax"
)

// Bounds for Literals: nesting, word count and total expanded text
const (
	maxLiteralDepth = MaxDepth
	maxLiteralWords = 4096
	maxLiteralBytes = 4 << 20
)

// Literals returns what bash may make of the words in src, for the secrets
// check: the value of every word in arguments, assignments and redirection
// targets, quotes and backslashes removed (gh\p_x is ghp_x),
// $'…' escapes read, and a variable assigned a known value earlier on the
// line ($A$B) replaced by it. A part only known at run time ($(…), $HOME,
// globs) is left out of its word, which is kept with what is known. A word
// with backslash escapes is also given as printf and echo -e would print
// it, and a word whose value contains quotes or backslashes is read again
// as shell code, so the words in code passed to sh -c and friends are
// returned too. Here-document bodies are left out: quotes are literal there
// A command line that doesn't parse returns nothing, and is denied elsewhere
//
// It also returns, run together, the arguments of every command in src
// that aren't options (printf %s%s gh p_x, echo -n in turn, or one
// command's words split up), as bash may print them one after another
// Exceeding a limit returns no partial result and ErrTooLarge or ErrTooComplex
func Literals(src string) (words []string, args string, err error) {
	l := literals{vars: map[string]string{}}
	l.read(src, 0)
	if l.err != nil {
		return nil, "", l.err
	}
	return l.out, l.args.String(), nil
}

type literals struct {
	out   []string
	args  strings.Builder
	vars  map[string]string
	bytes int
	err   error
}

// reserve charges text before building or retaining it, including temporary
// expansions and the joined output, so repeated assignments cannot grow unchecked
func (l *literals) reserve(n int) bool {
	if l.err != nil {
		return false
	}
	if n > maxLiteralBytes-l.bytes {
		l.err = ErrTooLarge
		return false
	}
	l.bytes += n
	return true
}

func (l *literals) write(b *strings.Builder, s string) {
	if l.reserve(len(s)) {
		b.WriteString(s)
	}
}

func (l *literals) add(w string) bool {
	if len(l.out) >= maxLiteralWords {
		l.err = ErrTooComplex
		return false
	}
	if !l.reserve(len(w) + 1) {
		return false
	}
	l.out = append(l.out, w)
	return true
}

func (l *literals) read(src string, depth int) {
	if l.err != nil {
		return
	}
	if depth > maxLiteralDepth {
		l.err = ErrTooComplex
		return
	}
	if len(src) > MaxBytes {
		l.err = ErrTooLarge
		return
	}
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(src), "")
	if err != nil {
		return
	}
	syntax.Walk(f, func(n syntax.Node) bool {
		if l.err != nil {
			return false
		}
		switch n := n.(type) {
		case *syntax.Redirect:
			if n.Hdoc != nil {
				// The target only: quotes in a here-document's body are literal
				if n.Word != nil {
					l.word(src, n.Word, depth)
				}
				return false
			}
		case *syntax.CallExpr:
			for _, w := range n.Args[min(1, len(n.Args)):] {
				if v, _ := l.value(w); !strings.HasPrefix(v, "-") {
					l.write(&l.args, v)
				}
				if l.err != nil {
					return false
				}
			}
		case *syntax.Assign:
			if n.Name != nil && n.Value != nil && n.Index == nil && n.Array == nil {
				v, _ := l.value(n.Value)
				if n.Append {
					if !l.reserve(len(l.vars[n.Name.Value]) + len(v)) {
						return false
					}
					v = l.vars[n.Name.Value] + v
				}
				if l.err != nil {
					return false
				}
				l.vars[n.Name.Value] = v
			}
		case *syntax.Word:
			return l.word(src, n, depth)
		}
		return true
	})
}

// word adds the values of w, and reports whether Walk should go into it:
// for the command substitutions in a word not wholly known
func (l *literals) word(src string, w *syntax.Word, depth int) bool {
	v, known := l.value(w)
	if l.err != nil {
		return false
	}
	if v != "" && !l.add(v) {
		return false
	}
	if strings.Contains(v, `\`) {
		if !l.reserve(2 * len(v)) {
			return false
		}
		printf, echo := cEscapes(v, false), cEscapes(v, true)
		if printf != v && !l.add(printf) || echo != v && echo != printf && !l.add(echo) {
			return false
		}
	}
	if !known {
		return true
	}
	raw := src[w.Pos().Offset():w.End().Offset()]
	if v != raw && strings.ContainsAny(v, `'"\`) {
		l.read(v, depth+1)
	}
	return false
}

// value returns w's value as bash makes it, without brace expansion
// ({1..99999999} stays one word), and whether all of it is known
func (l *literals) value(w *syntax.Word) (string, bool) {
	var b strings.Builder
	known := true
	for _, p := range w.Parts {
		if l.err != nil {
			return "", false
		}
		switch p := p.(type) {
		case *syntax.Lit:
			if l.reserve(len(p.Value)) {
				unescape(&b, p.Value, "")
			}
		case *syntax.SglQuoted:
			if p.Dollar {
				if l.reserve(len(p.Value)) {
					b.WriteString(cEscapes(p.Value, false))
				}
			} else {
				l.write(&b, p.Value)
			}
		case *syntax.DblQuoted:
			for _, q := range p.Parts {
				switch q := q.(type) {
				case *syntax.Lit:
					if l.reserve(len(q.Value)) {
						unescape(&b, q.Value, "$`\"\\\n")
					}
				case *syntax.ParamExp:
					known = l.param(&b, q) && known
				default:
					known = false
				}
			}
		case *syntax.ParamExp:
			known = l.param(&b, p) && known
		default:
			known = false
		}
	}
	return b.String(), known
}

// param writes the value of $NAME or ${NAME} when the line assigned it,
// and reports whether it did
func (l *literals) param(b *strings.Builder, p *syntax.ParamExp) bool {
	if p.Param == nil || p.Excl || p.Length || p.Width || p.Index != nil || p.Slice != nil || p.Repl != nil || p.Names != 0 || p.Exp != nil {
		return false
	}
	v, ok := l.vars[p.Param.Value]
	if ok {
		l.write(b, v)
	}
	return ok
}

// unescape writes s without its backslash escapes: every escape, or with
// only set non-empty, only those before a byte in it (inside double quotes)
// A backslash-newline is removed whole
func unescape(b *strings.Builder, s, only string) {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			if s[i+1] == '\n' {
				i++
				continue
			}
			if only == "" || strings.IndexByte(only, s[i+1]) >= 0 {
				i++
			}
		}
		b.WriteByte(s[i])
	}
}

// cEscapes reads the backslash escapes in s as bash reads them in $'…' and
// printf's format, or with echo as echo -e reads them (\0nnn for octal)
func cEscapes(s string, echo bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		c := s[i+1]
		i++
		switch c {
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
		case '\\', '\'', '"', '?':
			b.WriteByte(c)
		case 'x', 'u', 'U':
			n := map[byte]int{'x': 2, 'u': 4, 'U': 8}[c]
			j := i + 1
			for j < len(s) && j-i-1 < n && isHex(s[j]) {
				j++
			}
			if j == i+1 {
				b.WriteByte('\\')
				b.WriteByte(c)
				continue
			}
			if c == 'x' {
				v, _ := strconv.ParseUint(s[i+1:j], 16, 8) // at most 2 hex digits
				b.WriteByte(byte(v))
			} else if v, _ := strconv.ParseUint(s[i+1:j], 16, 32); v <= unicode.MaxRune && utf8.ValidRune(rune(v)) {
				b.WriteRune(rune(v))
			}
			i = j - 1
		default:
			if c < '0' || c > '7' {
				b.WriteByte('\\')
				b.WriteByte(c)
				continue
			}
			start, n := i, 3
			if echo {
				if c != '0' {
					b.WriteByte('\\')
					b.WriteByte(c)
					continue
				}
				start = i + 1
			}
			j := start
			var v byte // bash keeps the low byte
			for j < len(s) && j-start < n && s[j] >= '0' && s[j] <= '7' {
				v = v<<3 | (s[j] - '0')
				j++
			}
			b.WriteByte(v)
			i = j - 1
		}
	}
	return b.String()
}
