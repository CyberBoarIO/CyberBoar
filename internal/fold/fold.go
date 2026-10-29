// Package fold maps the spellings a filesystem may treat as one name to a
// single form, for rules that must err toward matching (deny, ask, and the
// programs the shell analyzer recognizes).
//
// macOS filesystems ignore case by default and ignore Unicode normalization
// (APFS, HFS+); HFS+ also ignores zero-width and direction-control characters
// in names (git's CVE-2014-9390). Folding goes further than any one of them:
// every letter of a case orbit (K, k and the Kelvin sign; S, s and long s) is
// one letter, and every format character and variation selector is dropped.
//
// Folding a glob can change what a bracket expression holds: [A-z] becomes
// [a-z] and loses the punctuation between Z and a, and [!e] then excludes E
// as well. A rule therefore matches the folded pattern against the folded
// name in addition to the pattern as written against the name as written,
// never instead of it. Only then does folding make a rule match more and
// never less.
package fold

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// String returns s folded: decomposed (NFD), without ignorable code points,
// case-folded, then recomposed (NFC). ASCII is only lower-cased.
// The result is a fixed point: String(String(s)) == String(s).
func String(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return unicodeFold(s)
		}
	}
	return strings.ToLower(s)
}

// unicodeFold is String for a string that has non-ASCII bytes.
func unicodeFold(s string) string {
	// norm preserves malformed UTF-8 and can stop decomposing after it.
	// Repair it first, as ranging over the string below would do anyway,
	// so composed and decomposed suffixes reach the same fixed point
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, string(utf8.RuneError))
	}
	var b strings.Builder
	for _, r := range norm.NFD.String(s) {
		if !Ignorable(r) {
			b.WriteRune(caseless(r))
		}
	}
	// NFC puts both spellings of one name, composed and decomposed, into the same form
	return norm.NFC.String(b.String())
}

// caseless maps every rune of a case orbit to one member: the lower-case form
// of the orbit's smallest rune. Unlike golang.org/x/text/cases.Fold, which
// swaps Cherokee upper and lower case, it is the same for every member.
func caseless(r rune) rune {
	m := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		m = min(m, f)
	}
	return unicode.ToLower(m)
}

// Ignorable reports whether r is dropped from names before comparing: format
// characters (zero-width spaces and joiners, direction controls, the byte
// order mark, soft hyphen), variation selectors, and the other default
// ignorable code points.
func Ignorable(r rune) bool {
	return unicode.In(r, unicode.Cf, unicode.Variation_Selector, unicode.Other_Default_Ignorable_Code_Point)
}
