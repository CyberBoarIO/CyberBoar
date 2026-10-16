// Package secrets finds credentials in text an agent is about to write or
// run: API tokens, private keys, passwords in URLs.
//
// The rules are gitleaks' default rule set (rules_gen.go, generated from
// gitleaks.toml by scripts/gen-secret-rules.py), applied the way gitleaks
// applies them: a rule runs only when one of its keywords is in the text;
// its secret is the first non-empty capture group (or secretGroup); a
// secret below the rule's entropy, or one an allowlist names, is not a
// finding. Unlike gitleaks, a "gitleaks:allow" comment allows nothing,
// since the agent writes the comments, and allowlists that need a file path
// or a commit never apply
package secrets

import (
	"context"
	"math"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// MaxText bounds the text Scan reads. Longer text is a finding of its own
// (TooLong): a secret past the limit would otherwise go unseen
const MaxText = 4 << 20

// TooLong is the Finding.Rule for text longer than MaxText
const TooLong = "too-long"

// Finding is a secret Scan found.
type Finding struct {
	Rule        string // the rule's id, e.g. "github-pat"
	Description string // what the rule finds, e.g. "Uncovered a GitHub Personal Access Token…"
	Start, End  int    // the secret's byte offsets in the text
}

type allowlist struct {
	target    string // "secret", "match" or "line"
	and       bool
	regexes   []string
	stopwords []string // lowercase
}

type ruleSpec struct {
	id, description string
	regex           string
	keywords        []string // lowercase
	entropy         float64
	secretGroup     int
	allow           []allowlist
}

type compiledAllow struct {
	allowlist
	res []*regexp.Regexp
}

type rule struct {
	ruleSpec
	once  sync.Once
	re    *regexp.Regexp
	allow []compiledAllow
}

var (
	compileOnce sync.Once
	rules       []rule
	global      compiledAllow
)

func compileAllow(a allowlist) compiledAllow {
	c := compiledAllow{allowlist: a}
	for _, s := range a.regexes {
		c.res = append(c.res, regexp.MustCompile(s))
	}
	return c
}

// compile sets the rules up once. A rule's regexes are compiled only when
// one of its keywords is in a text (rule.load): compiling all of them takes
// about 12 ms, and the hook is a new process for every tool call
// The patterns are fixed at build time, so MustCompile can't fail in a release
func compile() {
	global = compileAllow(globalAllow)
	rules = make([]rule, len(ruleSpecs))
	for i, s := range ruleSpecs {
		rules[i].ruleSpec = s
	}
}

func (r *rule) load() {
	r.once.Do(func() {
		r.re = regexp.MustCompile(r.regex)
		for _, a := range r.ruleSpec.allow {
			r.allow = append(r.allow, compileAllow(a))
		}
	})
}

// Rules returns the ids of every rule, sorted
func Rules() []string {
	ids := make([]string, len(ruleSpecs))
	for i, s := range ruleSpecs {
		ids[i] = s.id
	}
	slices.Sort(ids)
	return ids
}

// Scan returns the secrets in text, in the order of their offsets, skipping
// rules whose id is in ignore. Text longer than MaxText is reported as a
// single TooLong finding without being read. When ctx ends first, Scan
// returns its error and no findings; the hook then denies
func Scan(ctx context.Context, text string, ignore []string) ([]Finding, error) {
	if len(text) > MaxText {
		return []Finding{{Rule: TooLong, Description: "the text is too long to check for secrets"}}, nil
	}
	compileOnce.Do(compile)
	lower := asciiLower(text)
	var found []Finding
	for i := range rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r := &rules[i]
		if slices.Contains(ignore, r.id) {
			continue
		}
		ws := windows(lower, r.keywords)
		// A PEM key can span any number of lines, including blank lines
		if r.id == "private-key" && len(ws) > 0 {
			ws = [][2]int{{0, len(text)}}
		}
		if len(ws) > 0 {
			r.load()
		}
		for _, w := range ws {
			for _, m := range r.re.FindAllStringSubmatchIndex(text[w[0]:w[1]], -1) {
				for j := range m {
					if m[j] >= 0 {
						m[j] += w[0]
					}
				}
				if f, ok := r.finding(text, m); ok {
					found = append(found, f)
				}
			}
		}
	}
	slices.SortStableFunc(found, func(a, b Finding) int { return a.Start - b.Start })
	return found, nil
}

// asciiLower lowercases A-Z only. Unlike strings.ToLower it keeps every
// byte where it was (invalid UTF-8 and some letters change length), so
// offsets in it are offsets in the text. Every keyword is ASCII, so no
// keyword is missed
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// Around each keyword a rule's regex runs on this much text before and
// after it, instead of on all of it: a file the agent writes can be
// megabytes, and the hook has seconds. Every rule's match holds or sits
// next to one of its keywords. Private keys use the complete text instead,
// because their PEM formatting has no length bound. Some rules allow any
// distance on a line, and up to windowLines lines after it (curl-auth-header:
// curl, then -H on the same line or a continuation), so a window also covers
// the keyword's whole line and that many lines after it, however long
const (
	windowBefore = 1 << 10
	windowAfter  = 16 << 10
	windowLines  = 5
)

// windows returns the ranges of text to run a rule on: around each
// occurrence of one of its keywords, merged where they overlap, in order.
// A rule without keywords runs on all of text
func windows(lower string, keywords []string) [][2]int {
	if len(keywords) == 0 {
		return [][2]int{{0, len(lower)}}
	}
	var ws [][2]int
	for _, k := range keywords {
		// The keyword's line, and where its lines end: computed again only
		// on a new line, so a long line full of keywords is read once
		lineFrom, lineTo, linesTo := 0, -1, 0
		for off := 0; ; {
			i := strings.Index(lower[off:], k)
			if i < 0 {
				break
			}
			at := off + i
			if at > lineTo {
				lineFrom = max(lineTo+1, strings.LastIndexByte(lower[:at], '\n')+1)
				lineTo, linesTo = linesEnd(lower, at, 0)-1, linesEnd(lower, at, windowLines)
			}
			start := min(max(0, at-windowBefore), lineFrom)
			end := max(min(len(lower), at+len(k)+windowAfter), linesTo)
			ws = append(ws, [2]int{start, end})
			off = at + len(k)
		}
	}
	if len(ws) == 0 {
		return nil
	}
	slices.SortFunc(ws, func(a, b [2]int) int { return a[0] - b[0] })
	merged := ws[:1]
	for _, w := range ws[1:] {
		last := &merged[len(merged)-1]
		if w[0] <= last[1] {
			last[1] = max(last[1], w[1])
		} else {
			merged = append(merged, w)
		}
	}
	return merged
}

// linesEnd returns the offset of the end of the line holding offset at, n
// lines further on (or the end of s)
func linesEnd(s string, at, n int) int {
	for ; n >= 0; n-- {
		i := strings.IndexByte(s[at:], '\n')
		if i < 0 {
			return len(s)
		}
		at += i + 1
	}
	return at
}

// finding applies the rule's secret group, entropy and allowlists to one
// match (m as from FindAllStringSubmatchIndex)
func (r *rule) finding(text string, m []int) (Finding, bool) {
	match := strings.Trim(text[m[0]:m[1]], "\n")
	start := m[0] + strings.Index(text[m[0]:m[1]], match)
	sStart, sEnd := start, start+len(match)
	// The secret is a capture group of the regex applied to the match
	// alone, as gitleaks does it.
	if sub := r.re.FindStringSubmatchIndex(match); len(sub) >= 4 {
		g := 0
		if r.secretGroup > 0 {
			g = r.secretGroup
		} else {
			for i := 1; 2*i < len(sub); i++ {
				if sub[2*i] >= 0 && sub[2*i+1] > sub[2*i] {
					g = i
					break
				}
			}
		}
		if g > 0 && 2*g+1 < len(sub) && sub[2*g] >= 0 {
			sStart, sEnd = start+sub[2*g], start+sub[2*g+1]
		}
	}
	secret := text[sStart:sEnd]
	if r.entropy != 0 && entropy(secret) <= r.entropy {
		return Finding{}, false
	}
	line := lineAround(text, start, start+len(match))
	if global.allows(secret, match, line) {
		return Finding{}, false
	}
	for _, a := range r.allow {
		if a.allows(secret, match, line) {
			return Finding{}, false
		}
	}
	return Finding{Rule: r.id, Description: r.description, Start: sStart, End: sEnd}, true
}

// lineAround returns the lines of text that hold text[start:end]
func lineAround(text string, start, end int) string {
	if i := strings.LastIndexByte(text[:start], '\n'); i >= 0 {
		start = i + 1
	} else {
		start = 0
	}
	if i := strings.IndexByte(text[end:], '\n'); i >= 0 {
		end += i
	} else {
		end = len(text)
	}
	return text[start:end]
}

// allows reports whether the allowlist lets a finding through: any of its
// regexes or stopwords (both, with "and"). An empty allowlist allows nothing
func (a compiledAllow) allows(secret, match, line string) bool {
	target := secret
	switch a.target {
	case "match":
		target = match
	case "line":
		target = line
	}
	byRegex := false
	for _, re := range a.res {
		if re.MatchString(target) {
			byRegex = true
			break
		}
	}
	byWord := false
	lower := strings.ToLower(secret)
	for _, w := range a.stopwords {
		if strings.Contains(lower, w) {
			byWord = true
			break
		}
	}
	if a.and {
		return (len(a.res) == 0 || byRegex) && (len(a.stopwords) == 0 || byWord) && (len(a.res) > 0 || len(a.stopwords) > 0)
	}
	return byRegex || byWord
}

// entropy is the Shannon entropy of s in bits per character, as gitleaks computes it
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, c := range s {
		counts[c]++
	}
	var e float64
	inv := 1 / float64(len(s))
	for _, n := range counts {
		f := float64(n) * inv
		e -= f * math.Log2(f)
	}
	return e
}

// Redact returns text with every finding's secret replaced by
// "[REDACTED:rule]", for logs: the audit log must not become a store of the
// secrets the hook stopped. Text longer than MaxText is replaced whole
func Redact(text string, findings []Finding) string {
	if len(findings) == 1 && findings[0].Rule == TooLong {
		return "[REDACTED:" + TooLong + "]"
	}
	var b strings.Builder
	last := 0
	for _, f := range findings {
		if f.Start < last { // overlapping findings: the earlier one already covers it
			if f.End > last {
				last = f.End
			}
			continue
		}
		b.WriteString(text[last:f.Start])
		b.WriteString("[REDACTED:" + f.Rule + "]")
		last = f.End
	}
	b.WriteString(text[last:])
	return b.String()
}
