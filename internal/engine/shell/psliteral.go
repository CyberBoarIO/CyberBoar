package shell

import (
	"strings"

	"cyberboar.dev/cyberboar/internal/engine/shell/pwsh"
)

// PowerShellLiterals is Literals for PowerShell: the value of every string
// in src, quotes and escapes removed (gh`p_x is ghp_x), an expandable
// string also without its expansions ("gh$()p_x" is ghp_x), and, run
// together in order, the strings that aren't a command's name, as + or
// -join may join them ('gh' + 'p_x'). A string whose value holds quotes,
// backticks or backslashes is read again as PowerShell and as bash, so the
// words in code passed to pwsh -Command, bash -c and friends are returned
// too. A command line that doesn't parse returns nothing, and is denied
// elsewhere. The limits are Literals'.
func PowerShellLiterals(src string) (words []string, args string, err error) {
	l := literals{vars: map[string]string{}}
	l.readPS(src, 0)
	if l.err != nil {
		return nil, "", l.err
	}
	return l.out, l.args.String(), nil
}

func (l *literals) readPS(src string, depth int) {
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
	sb, err := pwsh.Parse(src)
	if err != nil {
		return
	}
	names := map[pwsh.Node]bool{}
	pwsh.Inspect(sb, func(n pwsh.Node) bool {
		if l.err != nil {
			return false
		}
		var v, text string
		switch n := n.(type) {
		case *pwsh.Command:
			if len(n.Elements) > 0 {
				names[n.Elements[0]] = true
			}
			return true
		case *pwsh.StringConstant:
			v, text = n.Value, n.Value
		case *pwsh.ExpandableString:
			v, text = n.Value, psFormatText(n.Format)
		default:
			return true
		}
		if !names[n] {
			l.write(&l.args, text)
		}
		if v != "" && !l.add(v) || text != v && text != "" && !l.add(text) {
			return false
		}
		if v != src && strings.ContainsAny(v, "'\"`\\") { // a bare word reads as itself again
			l.readPS(v, depth+1)
			l.read(v, depth+1)
		}
		return true // the strings in an expandable string's expansions
	})
}

// psFormatText is an expandable string's text without its expansions: its
// format with each {N} left out and {{ and }} read as braces.
func psFormatText(format string) string {
	var b strings.Builder
	for i := 0; i < len(format); i++ {
		c := format[i]
		switch {
		case (c == '{' || c == '}') && i+1 < len(format) && format[i+1] == c:
			b.WriteByte(c)
			i++
		case c == '{':
			if j := strings.IndexByte(format[i:], '}'); j > 1 && isDigits(format[i+1:i+j]) {
				i += j
				continue
			}
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
