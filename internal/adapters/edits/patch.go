package edits

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"mvdan.cc/sh/v3/syntax"

	"cyberboar.dev/cyberboar/internal/engine"
)

// These are the markers of the apply_patch grammar (codex-rs/apply-patch parser.rs).
const (
	beginPatch         = "*** Begin Patch"
	endPatch           = "*** End Patch"
	addFile            = "*** Add File: "
	deleteFile         = "*** Delete File: "
	updateFile         = "*** Update File: "
	moveTo             = "*** Move to: "
	endOfFile          = "*** End of File"
	changeContext      = "@@ "
	emptyChangeContext = "@@"
	environmentID      = "*** Environment ID:"
)

// chunk is one @@ section of an update, which replaces old lines with new ones.
type chunk struct {
	context  *string
	old, new []string
	// ctx pairs the indices in old and new of lines given as context.
	ctx [][2]int
	eof bool
}

// update is one "*** Update File" section, with its path, the destination of
// a move and its hunks.
type update struct {
	path, moveTo string
	chunks       []chunk
}

// Patch reads an apply_patch document as Codex does (codex-rs/apply-patch:
// parser.rs, streaming_parser.rs, file_update.rs, seek_sequence.rs) and
// returns the Rewrite of each file it updates, by the path its header names.
// For a moved file, the Rewrite of the source gives the content the
// destination gets. The files the document adds, whose content is the whole
// text, and the files it deletes are not in the map. A document Codex can't
// read is an error. A file the document touches twice gets a Rewrite that
// fails, because Codex applies the parts in turn, which Patch doesn't follow.
func Patch(doc string) (map[string]engine.Rewrite, error) {
	rewrites, _, err := PatchWithMoves(doc)
	return rewrites, err
}

// PatchWithMoves is Patch with the source paths of updates that move to another file.
func PatchWithMoves(doc string) (map[string]engine.Rewrite, map[string]bool, error) {
	updates, touched, err := parsePatch(doc)
	if err != nil {
		return nil, nil, err
	}
	out := map[string]engine.Rewrite{}
	moves := map[string]bool{}
	for _, u := range updates {
		if u.moveTo != "" {
			moves[u.path] = true
		}
		if touched[u.path] > 1 || u.moveTo != "" && touched[u.moveTo] > 1 {
			out[u.path] = func(string, bool) ([]string, error) {
				return nil, errors.New("the patch changes the file more than once; send one change per file")
			}
			continue
		}
		out[u.path] = func(old string, exists bool) ([]string, error) {
			if !exists {
				return nil, errors.New("the file to update doesn't exist")
			}
			return applyChunks(old, u.chunks)
		}
	}
	return out, moves, nil
}

// parsePatch returns the update sections of doc, and for each path, how many
// file headers name it, so Patch can refuse a file that is changed twice.
func parsePatch(doc string) (updates []update, touched map[string]int, err error) {
	lines := strings.Split(strings.TrimSpace(doc), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	if !bounded(lines) {
		// In lenient mode, Codex accepts the document wrapped in a heredoc's markers
		n := len(lines)
		if n < 4 || (lines[0] != "<<EOF" && lines[0] != "<<'EOF'" && lines[0] != `<<"EOF"`) || !strings.HasSuffix(lines[n-1], "EOF") ||
			!bounded(lines[1:n-1]) {
			return nil, nil, errors.New("not an apply_patch document")
		}
		lines = lines[1 : n-1]
	}
	touched = map[string]int{}
	const (
		started = iota
		adding
		deleting
		updating
		ended
	)
	mode := -1
	var cur *update
	// header handles the lines that start a file or end the patch
	header := func(t string) (bool, error) {
		if mode == started && strings.HasPrefix(t, environmentID) {
			return true, nil
		}
		emptyUpdate := func() error {
			if cur == nil {
				return nil
			}
			if len(cur.chunks) == 0 {
				return fmt.Errorf("update of %s is empty", cur.path)
			}
			if c := cur.chunks[len(cur.chunks)-1]; len(c.old) == 0 && len(c.new) == 0 {
				return errors.New("an update hunk has no lines")
			}
			return nil
		}
		var next int
		var path string
		switch {
		case t == endPatch:
			next = ended
		case strings.HasPrefix(t, addFile):
			next, path = adding, t[len(addFile):]
		case strings.HasPrefix(t, deleteFile):
			next, path = deleting, t[len(deleteFile):]
		case strings.HasPrefix(t, updateFile):
			next, path = updating, t[len(updateFile):]
		default:
			return false, nil
		}
		if err := emptyUpdate(); err != nil {
			return false, err
		}
		if cur != nil {
			updates = append(updates, *cur)
			cur = nil
		}
		if path != "" || next != ended {
			touched[path]++
		}
		if next == updating {
			cur = &update{path: path}
		}
		mode = next
		return true, nil
	}
	for _, line := range lines {
		t := strings.TrimSpace(line)
		switch mode {
		case -1:
			if t != beginPatch {
				return nil, nil, errors.New("the first line of the patch must be '*** Begin Patch'")
			}
			mode = started
		case started, deleting:
			if ok, err := header(t); err != nil || !ok {
				return nil, nil, errOrf(err, "not a valid hunk header: %q", t)
			}
		case adding:
			if ok, err := header(t); err != nil {
				return nil, nil, err
			} else if !ok && !strings.HasPrefix(line, "+") {
				return nil, nil, fmt.Errorf("not a valid hunk header: %q", t)
			}
		case updating:
			u := strings.TrimRight(line, " \t\r\n\v\f")
			if ok, err := header(u); err != nil {
				return nil, nil, err
			} else if ok {
				continue
			}
			if err := cur.line(line, u); err != nil {
				return nil, nil, err
			}
		case ended:
			if t != "" {
				return nil, nil, errors.New("the last line of the patch must be '*** End Patch'")
			}
		}
	}
	if mode != ended {
		return nil, nil, errors.New("the last line of the patch must be '*** End Patch'")
	}
	for _, u := range updates {
		if u.moveTo != "" {
			touched[u.moveTo]++
		}
	}
	return updates, touched, nil
}

// errOrf returns err when it is set, and otherwise an error formatted from format and args.
func errOrf(err error, format string, args ...any) error {
	if err != nil {
		return err
	}
	return fmt.Errorf(format, args...)
}

// bounded reports whether lines start and end with the patch's markers.
func bounded(lines []string) bool {
	return len(lines) > 0 && strings.TrimSpace(lines[0]) == beginPatch && strings.TrimSpace(lines[len(lines)-1]) == endPatch
}

// line reads one line of an update hunk. u is the line without trailing whitespace.
func (cur *update) line(line, u string) error {
	last := func() *chunk {
		if len(cur.chunks) == 0 {
			cur.chunks = append(cur.chunks, chunk{})
		}
		return &cur.chunks[len(cur.chunks)-1]
	}
	emptyLast := len(cur.chunks) > 0 && len(cur.chunks[len(cur.chunks)-1].old) == 0 && len(cur.chunks[len(cur.chunks)-1].new) == 0
	isContext := u == emptyChangeContext || strings.HasPrefix(u, changeContext)
	if len(cur.chunks) > 0 && cur.chunks[len(cur.chunks)-1].eof {
		if u == "" {
			return nil
		}
		if !isContext {
			return fmt.Errorf("expected an @@ line after the end of file, got %q", line)
		}
	}
	if len(cur.chunks) == 0 && cur.moveTo == "" {
		if p, ok := strings.CutPrefix(u, moveTo); ok {
			cur.moveTo = p
			return nil
		}
	}
	switch {
	case isContext && emptyLast:
		return fmt.Errorf("unexpected line in an update hunk: %q", line)
	case u == emptyChangeContext:
		cur.chunks = append(cur.chunks, chunk{})
	case strings.HasPrefix(u, changeContext):
		ctx := u[len(changeContext):]
		cur.chunks = append(cur.chunks, chunk{context: &ctx})
	case u == endOfFile:
		if emptyLast {
			return errors.New("an update hunk has no lines")
		}
		if len(cur.chunks) > 0 {
			cur.chunks[len(cur.chunks)-1].eof = true
		}
	case line == "":
		c := last()
		c.ctx = append(c.ctx, [2]int{len(c.old), len(c.new)})
		c.old, c.new = append(c.old, ""), append(c.new, "")
	case strings.HasPrefix(line, " "):
		c := last()
		c.ctx = append(c.ctx, [2]int{len(c.old), len(c.new)})
		c.old, c.new = append(c.old, line[1:]), append(c.new, line[1:])
	case strings.HasPrefix(line, "+"):
		c := last()
		c.new = append(c.new, line[1:])
	case strings.HasPrefix(line, "-"):
		c := last()
		c.old = append(c.old, line[1:])
	default:
		return fmt.Errorf("unexpected line in an update hunk: %q", line)
	}
	return nil
}

// replacement replaces n lines at line index at with lines.
type replacement struct {
	at, n int
	lines []string
}

// applyChunks returns the file after the chunks, as Codex writes it by
// default (lines in the patch's form, LF endings), and as it writes it
// when keeping line endings (context lines kept as the file has them).
func applyChunks(old string, chunks []chunk) ([]string, error) {
	lines := strings.Split(old, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	var normal, keep []replacement
	at := 0
	for _, c := range chunks {
		if c.context != nil {
			i, ok := seek(lines, []string{*c.context}, at, false)
			if !ok {
				return nil, fmt.Errorf("context %q isn't in the file", *c.context)
			}
			at = i + 1
		}
		if len(c.old) == 0 {
			i := len(lines)
			if i > 0 && lines[i-1] == "" {
				i--
			}
			normal = append(normal, replacement{i, 0, c.new})
			keep = append(keep, replacement{i, 0, c.new})
			continue
		}
		pattern, newLines := c.old, c.new
		i, ok := seek(lines, pattern, at, c.eof)
		if !ok && pattern[len(pattern)-1] == "" {
			pattern = pattern[:len(pattern)-1]
			if len(newLines) > 0 && newLines[len(newLines)-1] == "" {
				newLines = newLines[:len(newLines)-1]
			}
			i, ok = seek(lines, pattern, at, c.eof)
		}
		if !ok {
			return nil, errors.New("the lines to change aren't in the file")
		}
		normal = append(normal, replacement{i, len(pattern), newLines})
		kept := slices.Clone(newLines)
		for _, p := range c.ctx {
			if p[0] < len(pattern) && p[1] < len(kept) {
				kept[p[1]] = lines[i+p[0]]
			}
		}
		keep = append(keep, replacement{i, len(pattern), kept})
		at = i + len(pattern)
	}
	out := func(rs []replacement) string {
		slices.SortStableFunc(rs, func(a, b replacement) int { return a.at - b.at })
		res := slices.Clone(lines)
		for _, r := range slices.Backward(rs) {

			end := min(r.at+r.n, len(res))
			res = slices.Concat(res[:r.at], r.lines, res[end:])
		}
		if len(res) == 0 || res[len(res)-1] != "" {
			res = append(res, "")
		}
		return strings.Join(res, "\n")
	}
	return appendUnique(nil, out(normal), out(keep)), nil
}

// seek finds pattern in lines at or after start, as Codex's seek_sequence
// does. It tries an exact match first, then one that ignores trailing
// whitespace, then surrounding whitespace, and then typographic punctuation
// too. If eof is set, only the end of the file is tried.
func seek(lines, pattern []string, start int, eof bool) (int, bool) {
	if len(pattern) == 0 {
		return start, true
	}
	if len(pattern) > len(lines) {
		return 0, false
	}
	if eof {
		start = len(lines) - len(pattern)
	}
	for _, eq := range []func(a, b string) bool{
		func(a, b string) bool { return a == b },
		func(a, b string) bool { return trimEnd(a) == trimEnd(b) },
		func(a, b string) bool { return strings.TrimSpace(a) == strings.TrimSpace(b) },
		func(a, b string) bool { return punct(a) == punct(b) },
	} {
	next:
		for i := start; i <= len(lines)-len(pattern); i++ {
			for j, p := range pattern {
				if !eq(lines[i+j], p) {
					continue next
				}
			}
			return i, true
		}
	}
	return 0, false
}

// trimEnd removes trailing whitespace. Rust's trim functions and Go's agree
// on what is whitespace (Unicode's White_Space).
func trimEnd(s string) string { return strings.TrimRightFunc(s, unicode.IsSpace) }

// punct returns s as Codex's normalize function does, trimmed and with
// typographic dashes, quotes and spaces in ASCII.
func punct(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '‐', '‑', '‒', '–', '—', '―', '−':
			return '-'
		case '‘', '’', '‚', '‛':
			return '\''
		case '“', '”', '„', '‟':
			return '"'
		case ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', '　':
			return ' '
		}
		return r
	}, strings.TrimSpace(s))
}

// ShellPatch returns the patch a shell script hands to apply_patch, found the
// way Codex finds it (codex-rs/apply-patch invocation.rs). The script must be
// that one command with the patch in a here-document, alone or after
// `cd DIR &&`, and dir is then DIR. ok is false for any other script.
func ShellPatch(script string) (patch, dir string, ok bool) {
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(script), "")
	if err != nil || len(f.Stmts) != 1 {
		return "", "", false
	}
	s := f.Stmts[0]
	if b, isBin := s.Cmd.(*syntax.BinaryCmd); isBin {
		if s.Negated || s.Background || s.Coprocess || len(s.Redirs) > 0 {
			return "", "", false
		}
		cd, isCall := b.X.Cmd.(*syntax.CallExpr)
		if b.Op != syntax.AndStmt || !isCall || len(cd.Args) != 2 || len(cd.Assigns) > 0 || lit(cd.Args[0]) != "cd" ||
			b.X.Negated || b.X.Background || len(b.X.Redirs) > 0 {
			return "", "", false
		}
		if dir = lit(cd.Args[1]); dir == "" {
			return "", "", false
		}
		s = b.Y
	}
	call, isCall := s.Cmd.(*syntax.CallExpr)
	if !isCall || len(call.Args) != 1 || len(call.Assigns) > 0 || s.Negated || s.Background || s.Coprocess || len(s.Redirs) != 1 {
		return "", "", false
	}
	if name := lit(call.Args[0]); name != "apply_patch" && name != "applypatch" {
		return "", "", false
	}
	r := s.Redirs[0]
	if (r.Op != syntax.Hdoc && r.Op != syntax.DashHdoc) || r.Hdoc == nil {
		return "", "", false
	}
	// The word ends with the closing delimiter's line
	body := script[r.Hdoc.Pos().Offset():r.Hdoc.End().Offset()]
	before, _, ok := strings.CutLast(body, "\n")
	if !ok {
		return "", "", false
	}
	return strings.TrimRight(before, "\n"), dir, true
}

// lit returns a word that is one literal or quoted string, unquoted, or "".
func lit(w *syntax.Word) string {
	if len(w.Parts) != 1 {
		return ""
	}
	switch p := w.Parts[0].(type) {
	case *syntax.Lit:
		if !strings.ContainsAny(p.Value, `\`) {
			return p.Value
		}
	case *syntax.SglQuoted:
		if !p.Dollar {
			return p.Value
		}
	case *syntax.DblQuoted:
		if len(p.Parts) == 1 {
			if l, ok := p.Parts[0].(*syntax.Lit); ok && !strings.ContainsAny(l.Value, `\$`+"`") {
				return l.Value
			}
		}
	}
	return ""
}
