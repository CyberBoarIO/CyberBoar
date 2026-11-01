package shell

import (
	"errors"
	"strings"
	"unicode"
)

// psWild is one element of a PowerShell wildcard: a character, * or ?, or a
// set of characters and ranges.
type psWild struct {
	op     byte      // 'c', '*', '?' or '['
	r      rune      // the character, for 'c'
	ranges [][2]rune // a set's ranges, a single character as c-c
}

var errPSWildcard = errors.New("a PowerShell wildcard whose meaning isn't certain")

// psWildcard parses a PowerShell wildcard (about_Wildcards): * and ?, sets
// such as [abc] and [a-c], and ` making the next character literal. A set has
// no negation, so [!a] is ! or a and so is [^a]. A spelling whose meaning
// isn't certain is an error: an unclosed or empty set, a ] or - at a set's
// edge, a reversed range, a trailing `.
func psWildcard(p string) ([]psWild, error) {
	rs := []rune(p)
	var out []psWild
	for i := 0; i < len(rs); i++ {
		switch c := rs[i]; c {
		case '`':
			if i++; i == len(rs) {
				return nil, errPSWildcard
			}
			out = append(out, psWild{op: 'c', r: rs[i]})
		case '*', '?':
			out = append(out, psWild{op: byte(c)})
		case '[':
			var set []rune // the set's characters, literal - as '`'-escaped ones
			var escaped []bool
			for i++; i < len(rs) && rs[i] != ']'; i++ {
				esc := rs[i] == '`'
				if esc {
					if i++; i == len(rs) {
						return nil, errPSWildcard
					}
				}
				set, escaped = append(set, rs[i]), append(escaped, esc)
			}
			if i == len(rs) || len(set) == 0 {
				return nil, errPSWildcard
			}
			w := psWild{op: '['}
			for j := 0; j < len(set); j++ {
				if set[j] == '-' && !escaped[j] {
					return nil, errPSWildcard // at an edge, or after a range
				}
				lo, hi := set[j], set[j]
				if j+2 < len(set) && set[j+1] == '-' && !escaped[j+1] {
					hi = set[j+2]
					if hi < lo {
						return nil, errPSWildcard
					}
					j += 2
				}
				w.ranges = append(w.ranges, [2]rune{lo, hi})
			}
			out = append(out, w)
		default:
			out = append(out, psWild{op: 'c', r: c})
		}
	}
	return out, nil
}

// psWildcardMatch reports whether name matches the wildcard w, without case
// when nocase is set.
func psWildcardMatch(w []psWild, name string, nocase bool) bool {
	rs := []rune(name)
	one := func(p psWild, c rune) bool {
		switch p.op {
		case '?':
			return true
		case 'c':
			return c == p.r || nocase && (unicode.ToLower(c) == unicode.ToLower(p.r) ||
				unicode.ToUpper(c) == unicode.ToUpper(p.r))
		}
		for _, r := range p.ranges {
			for _, x := range []rune{c, unicode.ToLower(c), unicode.ToUpper(c)} {
				if r[0] <= x && x <= r[1] && (x == c || nocase) {
					return true
				}
			}
		}
		return false
	}
	pi, ni, star, mark := 0, 0, -1, 0
	for ni < len(rs) {
		switch {
		case pi < len(w) && w[pi].op == '*':
			star, mark = pi, ni
			pi++
		case pi < len(w) && one(w[pi], rs[ni]):
			pi++
			ni++
		case star >= 0:
			pi, mark = star+1, mark+1
			ni = mark
		default:
			return false
		}
	}
	for pi < len(w) && w[pi].op == '*' {
		pi++
	}
	return pi == len(w)
}

// psHasMeta reports whether a path segment is a PowerShell wildcard rather
// than a literal name: it holds *, ? or [, or a ` escaping one of them.
func psHasMeta(seg string) bool { return strings.ContainsAny(seg, "*?[`") }
