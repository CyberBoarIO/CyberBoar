// Package edits works out what an agent's file tools leave in a file, for
// the secrets check. Each function returns the engine.Rewrite of one kind of
// edit. The engine reads the file and looks for credentials in what the
// Rewrite returns that the file didn't hold before, so a secret put together
// from parts is found as well as a whole one.
//
// Where a tool's matching is looser than this package can follow exactly,
// the Rewrite errs on the side of an error. The engine then denies the
// write, and the agent retries with text that matches the file.
package edits

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"cyberboar.dev/cyberboar/internal/engine"
	"cyberboar.dev/cyberboar/internal/secrets"
)

// maxLoose bounds the size of a file a loose match is looked for in, because
// the search takes memory for each byte.
const maxLoose = 1 << 20

// maxResults bounds the number of contents one Rewrite returns, since each
// reading of where a loose match ends doubles them.
const maxResults = 4

// Replace is one edit of a file's text, which replaces Old with New. If All
// is set, every occurrence of Old is replaced.
type Replace struct {
	Old, New string
	All      bool
}

// Matching says how a tool looks for an edit's old text that isn't in the
// file as written.
type Matching int

const (
	// Loose is Strings' matching, which ignores whitespace, typographic
	// punctuation and escapes.
	Loose Matching = iota
	// Opencode is opencode's edit tool (tool/edit.ts in opencode 1.18.34). It
	// writes the old and new text with the file's line endings, and its
	// matching can also take a block by its first and last lines alone
	// (BlockAnchorReplacer, ContextAwareReplacer), whose lines between may
	// differ from the old text. Where that or replaceAll may change other text
	// than Loose finds, the Rewrite is an error.
	Opencode
)

// Strings returns the Rewrite of edits applied in turn, as Claude Code's
// Edit and MultiEdit, Copilot's str_replace and opencode's edit apply them.
// Old must be in the file once (at least once, with All), and an empty Old
// creates a file that doesn't exist or is empty.
// Every intermediate result is limited to secrets.MaxText bytes before allocation.
//
// When Old isn't in the file as written, the tools look for it more loosely,
// allowing for other whitespace and indentation, typographic quotes and
// dashes, and escapes. Strings does the same, ignoring all whitespace, those
// characters and escapes. A loose match can end in two places, at the
// matched text or with the blanks around it on its lines, so each such edit
// yields both results. An edit found nowhere, or in more than one place, is
// an error, because the tool refuses it or Strings can't tell which place it changes.
func Strings(edits []Replace) engine.Rewrite {
	return StringsMatching(edits, Loose)
}

// StringsMatching is Strings for a tool that matches as m says.
func StringsMatching(edits []Replace, m Matching) engine.Rewrite {
	return func(old string, exists bool) ([]string, error) {
		results := []string{old}
		for i, e := range edits {
			var next []string
			for _, r := range results {
				out, err := replace(r, exists || i > 0, e, m)
				if err != nil {
					if len(edits) > 1 {
						return nil, fmt.Errorf("edit %d: %w", i+1, err)
					}
					return nil, err
				}
				next = appendUnique(next, out...)
			}
			if len(next) > maxResults {
				return nil, errors.New("too many places the edits may apply to")
			}
			results = next
		}
		return results, nil
	}
}

// appendUnique appends the strings of add that list doesn't hold yet.
func appendUnique(list []string, add ...string) []string {
	for _, s := range add {
		dup := slices.Contains(list, s)
		if !dup {
			list = append(list, s)
		}
	}
	return list
}

// replace returns the possible results of applying e to content, which exists
// or not. Each result is one reading of where a loose match ends.
func replace(content string, exists bool, e Replace, m Matching) ([]string, error) {
	if m == Opencode && e.Old != "" && strings.Contains(content, "\r\n") {
		crlf := func(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n") }
		e.Old, e.New = crlf(e.Old), crlf(e.New)
	}
	if e.Old == "" {
		if exists && content != "" {
			return nil, errors.New("the old text is empty and the file isn't")
		}
		if err := checkSize(0, 1, len(e.New)); err != nil {
			return nil, err
		}
		return []string{e.New}, nil
	}
	if !exists {
		return nil, errors.New("the file doesn't exist")
	}
	switch n := strings.Count(content, e.Old); {
	case n == 1 || n > 0 && e.All:
		if err := checkSize(len(content)-n*len(e.Old), n, len(e.New)); err != nil {
			return nil, err
		}
		return []string{strings.ReplaceAll(content, e.Old, e.New)}, nil
	case n > 1:
		return nil, errors.New("the old text is in the file more than once")
	}
	if len(content) > maxLoose {
		return nil, errors.New("the old text isn't in the file as written")
	}
	spans, ambiguous := looseMatches(content, e.Old)
	switch {
	case len(spans) == 0:
		return nil, errors.New("the old text isn't in the file")
	case len(spans) > 1 && !e.All:
		return nil, errors.New("the old text matches more than one place in the file")
	case m == Opencode && ambiguous:
		return nil, errors.New("the old text isn't in the file as written, and read with and without its escapes it matches different places")
	case m == Opencode && len(spans) > 1:
		// replaceAll then replaces only the copies of the first place
		// opencode finds, which may be fewer than these
		return nil, errors.New("the old text isn't in the file as written, and replaceAll would change only some of the places it loosely matches")
	case m == Opencode && anchorElsewhere(content, e.Old, spans[0]):
		return nil, errors.New("the old text isn't in the file as written, and opencode may match it to another block with the same first and last lines")
	}
	kept := len(content)
	for _, s := range spans {
		kept -= s[1] - s[0]
	}
	// The wide reading removes at least as much text, so bounding the tight
	// result bounds both before either is built
	if err := checkSize(kept, len(spans), len(e.New)); err != nil {
		return nil, err
	}
	tight, wide := splice(content, spans, e.New, false), splice(content, spans, e.New, true)
	return appendUnique(nil, tight, wide), nil
}

// checkSize bounds kept + count*added without overflowing the multiplication.
func checkSize(kept, count, added int) error {
	if kept > secrets.MaxText || count > 0 && added > (secrets.MaxText-kept)/count {
		return engine.ErrRewriteTooLarge
	}
	return nil
}

// splice replaces each span of content with with. The spans are in order and
// don't overlap. If wide is set, the blanks around a span on its lines are
// replaced too.
func splice(content string, spans [][2]int, with string, wide bool) string {
	var b strings.Builder
	at := 0
	for _, s := range spans {
		start, end := s[0], s[1]
		if wide {
			for start > at && (content[start-1] == ' ' || content[start-1] == '\t') {
				start--
			}
			for end < len(content) && (content[end] == ' ' || content[end] == '\t' || content[end] == '\r') {
				end++
			}
		}
		b.WriteString(content[at:start])
		b.WriteString(with)
		at = end
	}
	b.WriteString(content[at:])
	return b.String()
}

// looseMatches returns where find is in content once whitespace, escapes
// and typographic punctuation are ignored. The spans of content it returns
// are in order and don't overlap, and each runs from the first to the last
// character matched. find is looked for as written first, and then with its
// escapes read. ambiguous reports that both are found, in different places.
func looseMatches(content, find string) (spans [][2]int, ambiguous bool) {
	norm, starts := normalize(content)
	end := func(i int) int {
		_, w := utf8.DecodeRuneInString(content[starts[i]:])
		return int(starts[i]) + w
	}
	search := func(f string) [][2]int {
		nf, _ := normalize(f)
		if nf == "" {
			return nil
		}
		var found [][2]int
		for off := 0; ; {
			i := strings.Index(norm[off:], nf)
			if i < 0 {
				break
			}
			at, last := off+i, off+i+len(nf)-1
			if at > 0 && starts[at-1] == starts[at] || last+1 < len(starts) && starts[last+1] == starts[last] {
				// Matching only part of a character, which invalid UTF-8 in
				// find can do, is not a match, and the spans would overlap
				off = at + 1
				continue
			}
			found = append(found, [2]int{int(starts[at]), end(last)})
			off = last + 1
		}
		return found
	}
	spans = search(find)
	if u := unescape(find); u != find {
		escaped := search(u)
		if len(spans) == 0 {
			return escaped, false
		}
		ambiguous = len(escaped) > 0 && !slices.Equal(escaped, spans)
	}
	return spans, ambiguous
}

// anchorElsewhere reports whether opencode's edit tool may replace other text
// than span, the one place find loosely matches, by taking a block whose
// first and last lines are find's (BlockAnchorReplacer and
// ContextAwareReplacer). It errs on the side of true: it ignores how similar
// the lines between are, and it trims more characters than JavaScript's trim,
// so that more lines are equal. Replacing span as splice does, tightly or
// widely, is the same as replacing the block of its lines.
func anchorElsewhere(content, find string, span [2]int) bool {
	fl := strings.Split(find, "\n")
	if len(fl) < 3 {
		return false
	}
	if fl[len(fl)-1] == "" {
		fl = fl[:len(fl)-1]
	}
	first, last := trimJS(fl[0]), trimJS(fl[len(fl)-1])
	size, delta := len(fl), max(1, len(fl)/4)

	lines := strings.Split(content, "\n")
	starts := make([]int, len(lines))
	var lasts []int
	for i, at := 0, 0; i < len(lines); i++ {
		starts[i] = at
		at += len(lines[i]) + 1
		if trimJS(lines[i]) == last {
			lasts = append(lasts, i)
		}
	}
	tight := span
	wide := [2]int{span[0], span[1]}
	for wide[0] > 0 && (content[wide[0]-1] == ' ' || content[wide[0]-1] == '\t') {
		wide[0]--
	}
	for wide[1] < len(content) && (content[wide[1]] == ' ' || content[wide[1]] == '\t' || content[wide[1]] == '\r') {
		wide[1]++
	}
	for i := range lines {
		if trimJS(lines[i]) != first {
			continue
		}
		// The block's last line j is at least two lines on, and its size is
		// within delta of find's
		lo, hi := max(i+2, i+size-1-delta), i+size-1+delta
		for k := sort.SearchInts(lasts, lo); k < len(lasts) && lasts[k] <= hi; k++ {
			j := lasts[k]
			block := [2]int{starts[i], starts[j] + len(lines[j])}
			if block != tight && block != wide {
				return true
			}
		}
	}
	return false
}

// trimJS trims what JavaScript's String.prototype.trim does and more, which
// for the comparisons in anchorElsewhere errs on the side of equal lines.
func trimJS(s string) string {
	return strings.TrimFunc(s, func(r rune) bool { return unicode.IsSpace(r) || r == '\uFEFF' })
}

// normalize drops whitespace from s and maps typographic punctuation to
// ASCII as Codex's patch matching does (codex-rs/apply-patch
// seek_sequence.rs). starts[i] is the offset in s of the character that
// byte i of norm came from.
func normalize(s string) (norm string, starts []int32) {
	var b strings.Builder
	for i, r := range s {
		_, w := utf8.DecodeRuneInString(s[i:])
		if unicode.IsSpace(r) {
			continue
		}
		switch r {
		case '‐', '‑', '‒', '–', '—', '―', '−':
			r = '-'
		case '‘', '’', '‚', '‛':
			r = '\''
		case '“', '”', '„', '‟':
			r = '"'
		}
		n := b.Len()
		if r == utf8.RuneError && w == 1 {
			b.WriteByte(s[i]) // invalid UTF-8 kept as it is
		} else {
			b.WriteRune(r)
		}
		for range b.Len() - n {
			starts = append(starts, int32(i)) // #nosec G115 -- i < maxLoose
		}
	}
	return b.String(), starts
}

// unescape reads the escapes opencode's edit tool also tries (\n, \t, \r, quotes, \\, \$).
func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch c := s[i+1]; c {
			case 'n':
				b.WriteByte('\n')
				i++
				continue
			case 't':
				b.WriteByte('\t')
				i++
				continue
			case 'r':
				b.WriteByte('\r')
				i++
				continue
			case '\'', '"', '`', '\\', '\n', '$':
				b.WriteByte(c)
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Insert returns the Rewrite of text inserted after line n of a file, where
// 0 is before the first line, as Copilot's str_replace_editor inserts it. The
// Rewrite returns the file both with and without a line break after the
// text, since it can't tell which one the tool writes.
func Insert(n int, text string) engine.Rewrite {
	return func(old string, exists bool) ([]string, error) {
		if !exists {
			return nil, errors.New("the file doesn't exist")
		}
		if err := checkSize(len(old), 1, len(text)); err != nil {
			return nil, err
		}
		if len(old)+len(text) == secrets.MaxText {
			return nil, engine.ErrRewriteTooLarge // the reading with a newline exceeds the limit
		}
		pos := 0
		for i := range n {
			j := strings.IndexByte(old[pos:], '\n')
			if j < 0 {
				if i == n-1 && pos < len(old) {
					return appendUnique(nil, old+"\n"+text, old+text), nil
				}
				return nil, fmt.Errorf("the file has fewer than %d lines", n)
			}
			pos += j + 1
		}
		return appendUnique(nil, old[:pos]+text+"\n"+old[pos:], old[:pos]+text+old[pos:]), nil
	}
}
