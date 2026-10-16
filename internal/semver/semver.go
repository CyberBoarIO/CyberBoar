// Package semver compares release versions (Semantic Versioning 2.0.0), as
// release tags and the binary's own version spell them: 1.4.2, v1.4.2,
// 1.0.0-rc.2. It parses only what a version check needs and never panics
package semver

import "strings"

// version is a parsed version: the numeric core and the pre-release
// identifiers, each as written (digits only, no leading zeros, in the numeric
// ones). Build metadata takes no part in precedence and is dropped
type version struct {
	core [3]string
	pre  []string
}

// parse reads s, with or without a leading "v". It reports false for
// anything that isn't a semantic version
func parse(s string) (version, bool) {
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		if !identifiers(s[i+1:], false) {
			return version{}, false
		}
		s = s[:i]
	}
	var v version
	core, pre, hasPre := strings.Cut(s, "-")
	if hasPre {
		if !identifiers(pre, true) {
			return version{}, false
		}
		v.pre = strings.Split(pre, ".")
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return version{}, false
	}
	for i, p := range parts {
		if !numeric(p) {
			return version{}, false
		}
		v.core[i] = p
	}
	return v, true
}

// identifiers reports whether s is a dot-separated list of non-empty
// identifiers of ASCII letters, digits and hyphens
func identifiers(s string, pre bool) bool {
	for id := range strings.SplitSeq(s, ".") {
		if id == "" {
			return false
		}
		digits := true
		for i := 0; i < len(id); i++ {
			c := id[i]
			switch {
			case c >= '0' && c <= '9':
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '-':
				digits = false
			default:
				return false
			}
		}
		if pre && digits && !numeric(id) {
			return false
		}
	}
	return true
}

// numeric reports whether s is a number without leading zeros
func numeric(s string) bool {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// compareNumbers compares two numbers without leading zeros, of any length
func compareNumbers(a, b string) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// compare orders a and b by semantic version precedence
func compare(a, b version) int {
	for i := range a.core {
		if c := compareNumbers(a.core[i], b.core[i]); c != 0 {
			return c
		}
	}
	// A pre-release comes before the release it leads to
	switch {
	case a.pre == nil && b.pre == nil:
		return 0
	case a.pre == nil:
		return 1
	case b.pre == nil:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		x, y := a.pre[i], b.pre[i]
		xn, yn := numeric(x), numeric(y)
		var c int
		switch {
		case xn && yn:
			c = compareNumbers(x, y)
		case xn:
			c = -1
		case yn:
			c = 1
		default:
			c = strings.Compare(x, y)
		}
		if c != 0 {
			return c
		}
	}
	switch {
	case len(a.pre) < len(b.pre):
		return -1
	case len(a.pre) > len(b.pre):
		return 1
	}
	return 0
}

// Valid reports whether s is a semantic version, with or without a leading "v"
func Valid(s string) bool {
	_, ok := parse(s)
	return ok
}

// AtLeast reports whether version is minimum or a later one. A version that
// doesn't parse, such as a development build's "dev", is never at least
// anything: a check that can't place a binary doesn't let it through
func AtLeast(version, minimum string) bool {
	v, ok := parse(version)
	if !ok {
		return false
	}
	m, ok := parse(minimum)
	if !ok {
		return false
	}
	return compare(v, m) >= 0
}
