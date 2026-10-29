package shell

import (
	"strings"
	"testing"
)

func TestParseOptsLongPrefixes(t *testing.T) {
	grep := optSpec{long: set("binary-files"), flags: set("binary"), abbrev: true}
	for _, c := range []struct {
		spec       optSpec
		args, rest string
		has        string // an option has finds
	}{
		{optSpec{long: set("signal"), abbrev: true}, "--sig KILL cmd", "cmd", "signal"},
		{optSpec{long: set("signal")}, "--sig KILL cmd", "KILL cmd", ""}, // takes no abbreviations
		{grep, "--binary pat", "pat", "binary"},
		{grep, "--binary-f text pat", "pat", "binary-files"},
	} {
		var args []Elem
		for w := range strings.FieldsSeq(c.args) {
			args = append(args, Elem{Kind: Lit, Text: w})
		}
		p := parseOpts(args, c.spec)
		var rest []string
		for _, e := range p.rest {
			rest = append(rest, e.Text)
		}
		if got := strings.Join(rest, " "); got != c.rest {
			t.Errorf("%q: operands %q, want %q", c.args, got, c.rest)
		}
		for l := range c.spec.long {
			if want := l == c.has; p.has(l) != want {
				t.Errorf("%q: has(%q) = %v", c.args, l, !want)
			}
		}
	}
}
