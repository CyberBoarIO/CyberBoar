package pwsh_test

import (
	"testing"

	"cyberboar.dev/cyberboar/internal/engine/shell/pwsh"
)

// An expandable string keeps the format string PowerShell builds for it,
// which is what PowerShell formats at run time
// An escaped $ and an expansion share a Value but not a Format
// The expected formats follow PowerShell's tokenizer, including the braces it leaves single in a bare word
func TestExpandableStringFormat(t *testing.T) {
	for _, tc := range []struct{ in, value, format string }{
		{"f \"`$x $x\"", "$x $x", "$x {0}"},
		{"f \"$x `$x\"", "$x $x", "{0} $x"},
		{"f a`$x$x", "a$x$x", "a$x{0}"},
		{"f a$x`$x", "a$x$x", "a{0}$x"},
		{`"x$($a)y"`, "x$($a)y", "x{0}y"},
		{`f "$a-$($b)"`, "$a-$($b)", "{0}-{1}"},
		{`f "a""$x"`, `a"$x`, `a"{0}`},
		{`f "{$x}"`, "{$x}", "{{{0}}}"},
		{"f @\"\n{$x}\n\"@", "{$x}", "{{{0}}}"},
		{"f @\"\n$x\r\n\"@", "$x", "{0}"},
		{`f a"{$x}"$y`, "a{$x}$y", "a{{{0}}}{1}"},
		{"f a`{$x", "a{$x", "a{{{0}"},
		{`f "$a$a$a$a$a$a$a$a$a$a$a"`, "$a$a$a$a$a$a$a$a$a$a$a", "{0}{1}{2}{3}{4}{5}{6}{7}{8}{9}{10}"},
		// PowerShell copies a single-quoted part of a bare word, and an
		// escaped first character, without doubling their braces
		{`f a'{0}'$x`, "a{0}$x", "a{0}{0}"},
		{"f `{$x", "{$x", "{{0}"},
	} {
		sb, err := pwsh.Parse(tc.in)
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		var got []*pwsh.ExpandableString
		pwsh.Inspect(sb, func(n pwsh.Node) bool {
			if e, ok := n.(*pwsh.ExpandableString); ok {
				got = append(got, e)
			}
			return true
		})
		if len(got) != 1 {
			t.Errorf("%q: %d expandable strings, want 1", tc.in, len(got))
			continue
		}
		if e := got[0]; e.Value != tc.value || e.Format != tc.format {
			t.Errorf("%q: value %q format %q, want %q and %q", tc.in, e.Value, e.Format, tc.value, tc.format)
		}
	}
}
