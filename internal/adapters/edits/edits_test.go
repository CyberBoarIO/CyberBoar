package edits

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/internal/engine"
	"cyberboar.dev/cyberboar/internal/secrets"
)

func apply(t *testing.T, r engine.Rewrite, old string, exists bool) []string {
	t.Helper()
	out, err := r(old, exists)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	return out
}

func TestStrings(t *testing.T) {
	for _, c := range []struct {
		name  string
		old   string
		edits []Replace
		want  []string
	}{
		{"one", "a b c", []Replace{{Old: "b", New: "B"}}, []string{"a B c"}},
		{"in turn", "a b c", []Replace{{Old: "b", New: "x"}, {Old: "x c", New: "y"}}, []string{"a y"}},
		{"all", "a a", []Replace{{Old: "a", New: "b", All: true}}, []string{"b b"}},
		{"create", "", []Replace{{Old: "", New: "new"}}, []string{"new"}},
		{"loose whitespace", "x =   1\n", []Replace{{Old: "x = 1", New: "x = 2"}}, []string{"x = 2\n"}},
		{"loose, blanks around", "  if x {\n", []Replace{{Old: "if  x {", New: "if y {"}}, []string{"  if y {\n", "if y {\n"}},
		{"loose quotes", "s := “q”\n", []Replace{{Old: `s := "q"`, New: "s := 1"}}, []string{"s := 1\n"}},
		{"loose escapes", "a\nb\n", []Replace{{Old: `a\nb`, New: "c"}}, []string{"c\n"}},
		{"loose, both readings", "x\n\t  a b  \t\ny", []Replace{{Old: "a  b", New: "Z"}}, []string{"x\n\t  Z  \t\ny", "x\nZ\ny"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := apply(t, Strings(c.edits), c.old, c.old != "" || c.name != "create")
			if !slices.Equal(got, c.want) {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
	for _, c := range []struct {
		name   string
		old    string
		exists bool
		edits  []Replace
		err    string
	}{
		{"missing", "a", true, []Replace{{Old: "z", New: "y"}}, "isn't in the file"},
		{"twice", "a a", true, []Replace{{Old: "a", New: "b"}}, "more than once"},
		{"loosely twice", "a  b a\tb", true, []Replace{{Old: "a b", New: "c"}}, "more than one place"},
		{"no file", "", false, []Replace{{Old: "a", New: "b"}}, "doesn't exist"},
		{"create over a file", "x", true, []Replace{{Old: "", New: "b"}}, "isn't"},
		{"blank old", "x", true, []Replace{{Old: " \n", New: "b"}}, "isn't in the file"},
		{"second edit", "a", true, []Replace{{Old: "a", New: "b"}, {Old: "a", New: "c"}}, "edit 2"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Strings(c.edits)(c.old, c.exists); err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("err %v, want %q", err, c.err)
			}
		})
	}
}

// Every loose reading doubles the results; past maxResults it is an error
func TestStringsBounded(t *testing.T) {
	old := strings.Repeat(" a1 \n", 1) + " a2 \n a3 \n"
	es := []Replace{{Old: "a1", New: "b1"}, {Old: "a2", New: "b2"}, {Old: "a3", New: "b3"}}
	for i := range es {
		es[i].Old = strings.Join(strings.Split(es[i].Old, ""), " ")
	}
	if _, err := Strings(es)(old, true); err == nil {
		t.Error("eight readings accepted")
	}
}

func TestStringsOutputLimit(t *testing.T) {
	boundary := strings.Repeat("b", secrets.MaxText)
	for _, tc := range []struct {
		name   string
		old    string
		edits  []Replace
		length int
		tooBig bool
	}{
		{"exact expansion", strings.Repeat("a", 64<<10), []Replace{{Old: "a", New: strings.Repeat("b", 128), All: true}}, 0, true},
		{"loose expansion", strings.Repeat("a ", 32<<10), []Replace{{Old: "a\t", New: strings.Repeat("b", 256), All: true}}, 0, true},
		{"second edit expands", strings.Repeat("a", 64<<10), []Replace{{Old: "a", New: "x", All: true}, {Old: "x", New: strings.Repeat("b", 128), All: true}}, 0, true},
		{"creation too large", "", []Replace{{New: boundary + "x"}}, 0, true},
		{"exact at limit", strings.Repeat("a", 32<<10), []Replace{{Old: "a", New: strings.Repeat("b", 128), All: true}}, secrets.MaxText, false},
		{"exact one byte over", strings.Repeat("a", 32<<10) + "x", []Replace{{Old: "a", New: strings.Repeat("b", 128), All: true}}, 0, true},
		{"loose at limit", "a b", []Replace{{Old: "a  b", New: boundary}}, secrets.MaxText, false},
		{"one loose reading too large", " a b ", []Replace{{Old: "a  b", New: boundary}}, 0, true},
		{"large source shrinks", strings.Repeat("aa", secrets.MaxText), []Replace{{Old: "aa", New: "b", All: true}}, secrets.MaxText, false},
		{"large source removed", strings.Repeat("a", secrets.MaxText+1), []Replace{{Old: "a", All: true}}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := Strings(tc.edits)(tc.old, tc.old != "")
			if tc.tooBig {
				if !errors.Is(err, engine.ErrRewriteTooLarge) || len(out) != 0 {
					t.Fatalf("got %d results, error %v; want ErrRewriteTooLarge", len(out), err)
				}
				return
			}
			if err != nil || len(out) == 0 {
				t.Fatalf("rewrite failed: %v", err)
			}
			for _, result := range out {
				if len(result) != tc.length {
					t.Fatalf("result length %d, want %d", len(result), tc.length)
				}
			}
		})
	}
}

func TestRewriteSizeOverflow(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	if err := checkSize(0, maxInt, 2); !errors.Is(err, engine.ErrRewriteTooLarge) {
		t.Fatalf("overflowing multiplication accepted: %v", err)
	}
}

// opencode's matching: line endings as in the file, and an error where its
// looser matchers may change other text than the loose match
func TestStringsOpencode(t *testing.T) {
	for _, c := range []struct {
		name, old string
		e         Replace
		loose     []string // with Loose
		opencode  []string // with Opencode; nil for an error
	}{
		{
			name:  "another block with the same first and last lines",
			old:   "A\na b c d e f g h\nB\n--\nA\nabcdefgX\nB\n",
			e:     Replace{Old: "A\nabcdefgh\nB", New: "N"},
			loose: []string{"N\n--\nA\nabcdefgX\nB\n"},
		},
		{
			name:     "the block is the loose match",
			old:      "A\na  b\nB\n",
			e:        Replace{Old: "A\na b\nB", New: "N"},
			loose:    []string{"N\n"},
			opencode: []string{"N\n"},
		},
		{
			name:     "an anchor block out of size range",
			old:      "  A\nx y\nB\n--\nA\n1\n2\n3\n4\nB\n",
			e:        Replace{Old: "A\nxy\nB", New: "N"},
			loose:    []string{"  N\n--\nA\n1\n2\n3\n4\nB\n", "N\n--\nA\n1\n2\n3\n4\nB\n"},
			opencode: []string{"  N\n--\nA\n1\n2\n3\n4\nB\n", "N\n--\nA\n1\n2\n3\n4\nB\n"},
		},
		{
			name:     "CRLF file",
			old:      "a\r\nb\r\nc\r\n",
			e:        Replace{Old: "a\nb", New: "x\ny"},
			loose:    []string{"x\ny\r\nc\r\n", "x\ny\nc\r\n"},
			opencode: []string{"x\r\ny\r\nc\r\n"},
		},
		{
			name:  "replaceAll of loose matches",
			old:   "x = a b\ny = a  b\n",
			e:     Replace{Old: "a   b", New: "Q", All: true},
			loose: []string{"x = Q\ny = Q\n", "x =Q\ny =Q\n"},
		},
		{
			name:     "replaceAll of exact matches",
			old:      "a b\na b\n",
			e:        Replace{Old: "a b", New: "Q", All: true},
			loose:    []string{"Q\nQ\n"},
			opencode: []string{"Q\nQ\n"},
		},
		{
			name:  "escapes read and unread match different places",
			old:   "s = \"a\\nb\"\na\nb\n",
			e:     Replace{Old: "a\\n b", New: "Q"},
			loose: []string{"s = \"Q\"\na\nb\n"},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := apply(t, Strings([]Replace{c.e}), c.old, true); !slices.Equal(got, c.loose) {
				t.Errorf("loose: got %q, want %q", got, c.loose)
			}
			got, err := StringsMatching([]Replace{c.e}, Opencode)(c.old, true)
			switch {
			case c.opencode == nil && err == nil:
				t.Errorf("opencode: got %q, want an error", got)
			case c.opencode != nil && (err != nil || !slices.Equal(got, c.opencode)):
				t.Errorf("opencode: got %q, %v, want %q", got, err, c.opencode)
			}
		})
	}
}

// The anchor check takes time in the size of the file, not in its lines times the old text's
func TestAnchorElsewhereLinear(t *testing.T) {
	old := strings.Repeat("x\n", 400_000) + "x\ny  z\nw\n"
	find := strings.Repeat("x\n", 1000) + "y z\nw"
	start := time.Now()
	if _, err := StringsMatching([]Replace{{Old: find, New: "N"}}, Opencode)(old, true); err == nil {
		t.Error("blocks starting at other x lines and ending at w: no error")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
}

func TestNormalize(t *testing.T) {
	s := "a – b\xffc"
	norm, starts := normalize(s)
	if norm != "a-b\xffc" {
		t.Fatalf("norm %q", norm)
	}
	if want := []int32{0, 2, 6, 7, 8}; !slices.Equal(starts, want) {
		t.Errorf("starts %v, want %v", starts, want)
	}
	if spans, _ := looseMatches(s, "a-b"); len(spans) != 1 || s[spans[0][0]:spans[0][1]] != "a – b" {
		t.Errorf("spans %v", spans)
	}
}

func TestInsert(t *testing.T) {
	got := apply(t, Insert(1, "X"), "a\nb\n", true)
	if want := []string{"a\nX\nb\n", "a\nXb\n"}; !slices.Equal(got, want) {
		t.Errorf("got %q", got)
	}
	got = apply(t, Insert(2, "X"), "a\nb", true)
	if want := []string{"a\nb\nX", "a\nbX"}; !slices.Equal(got, want) {
		t.Errorf("after the last line: got %q", got)
	}
	if _, err := Insert(3, "X")("a\nb\n", true); err == nil {
		t.Error("past the end accepted")
	}
	if _, err := Insert(0, "X")("", false); err == nil {
		t.Error("missing file accepted")
	}
}

func TestInsertOutputLimit(t *testing.T) {
	for _, tc := range []struct {
		name, old, text string
		tooBig          bool
	}{
		{"with newline at limit", "a", strings.Repeat("b", secrets.MaxText-2), false},
		{"newline exceeds limit", "a", strings.Repeat("b", secrets.MaxText-1), true},
		{"text exceeds limit", "a", strings.Repeat("b", secrets.MaxText), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := Insert(0, tc.text)(tc.old, true)
			if tc.tooBig {
				if !errors.Is(err, engine.ErrRewriteTooLarge) || len(out) != 0 {
					t.Fatalf("got %d results, error %v; want ErrRewriteTooLarge", len(out), err)
				}
				return
			}
			if err != nil || len(out) != 2 {
				t.Fatalf("insert failed: %v", err)
			}
			for _, result := range out {
				if len(result) > secrets.MaxText {
					t.Fatalf("result exceeds scan limit: %d", len(result))
				}
			}
		})
	}
}

func patch(body string) string { return "*** Begin Patch\n" + body + "*** End Patch\n" }

// Cases from Codex's own tests (codex-rs/apply-patch lib.rs), and its matching rules
func TestPatch(t *testing.T) {
	for _, c := range []struct {
		name, doc, path, old string
		want                 []string
	}{
		{"update", patch("*** Update File: f\n@@\n foo\n-bar\n+baz\n"), "f", "foo\nbar\n", []string{"foo\nbaz\n"}},
		{"two chunks", patch("*** Update File: f\n@@\n foo\n-bar\n+BAR\n@@\n baz\n-qux\n+QUX\n"), "f", "foo\nbar\nbaz\nqux\n", []string{"foo\nBAR\nbaz\nQUX\n"}},
		{"interleaved", patch("*** Update File: f\n@@\n a\n-b\n+B\n@@\n c\n d\n-e\n+E\n@@\n f\n+g\n*** End of File\n"), "f", "a\nb\nc\nd\ne\nf\n", []string{"a\nB\nc\nd\nE\nf\ng\n"}},
		{"addition then removal", patch("*** Update File: f\n@@\n+added\n@@\n-x\n"), "f", "x\ny\n", []string{"y\nadded\n"}},
		{"context line", patch("*** Update File: f\n@@ func b\n-x\n+y\n"), "f", "func a\nx\nfunc b\nx\n", []string{"func a\nx\nfunc b\ny\n"}},
		{"unicode dash", patch("*** Update File: f\n@@\n-import asyncio  # local import - avoids top-level dep\n+import asyncio  # HELLO\n"), "f",
			"import asyncio  # local import – avoids top-level dep\n", []string{"import asyncio  # HELLO\n"}},
		{"context kept as the file has it", patch("*** Update File: f\n@@\n a – b\n+c\n"), "f", "a — b\n", []string{"a – b\nc\n", "a — b\nc\n"}},
		{"trailing blanks", patch("*** Update File: f\n@@\n-a\n+b\n"), "f", "a  \n", []string{"b\n"}},
		{"moved", patch("*** Update File: f\n*** Move to: g\n@@\n-a\n+b\n"), "f", "a\n", []string{"b\n"}},
		{"heredoc markers", "<<'EOF'\n" + patch("*** Update File: f\n@@\n-a\n+b\n") + "EOF\n", "f", "a\n", []string{"b\n"}},
		{"end of file", patch("*** Update File: f\n@@\n-a\n+b\n*** End of File\n"), "f", "a\nx\na\n", []string{"a\nx\nb\n"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			rs, err := Patch(c.doc)
			if err != nil {
				t.Fatal(err)
			}
			if rs[c.path] == nil {
				t.Fatalf("no rewrite for %s in %v", c.path, rs)
			}
			if got := apply(t, rs[c.path], c.old, true); !slices.Equal(got, c.want) {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestPatchErrors(t *testing.T) {
	for _, doc := range []string{
		"",
		"*** Begin Patch\n*** Update File: f\n@@\n-a\n",
		patch("*** Update File: f\n"),
		patch("*** Update File: f\nnot a hunk line\n"),
		patch("*** Frobnicate File: f\n"),
		patch("*** Update File: f\n@@\n@@\n-a\n"),
		patch("*** Add File: f\nno plus\n"),
		patch("*** Update File: f\n@@\n-a\n*** End of File\nb\n"),
		"*** Begin Patch\n*** Add File: f\n+a\n*** End Patch\nmore\n",
	} {
		if _, err := Patch(doc); err == nil {
			t.Errorf("%q: no error", doc)
		}
	}
	rs, err := Patch(patch("*** Update File: f\n@@\n-a\n+b\n*** Update File: f\n@@\n-b\n+c\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rs["f"]("a\n", true); err == nil {
		t.Error("a file updated twice was worked out")
	}
	rs, _ = Patch(patch("*** Update File: f\n@@\n-zzz\n+b\n"))
	if _, err := rs["f"]("a\n", true); err == nil {
		t.Error("lines that aren't there were applied")
	}
	if _, err := rs["f"]("", false); err == nil {
		t.Error("a missing file was updated")
	}
	rs, _ = Patch(patch("*** Add File: n\n+x\n*** Delete File: d\n"))
	if len(rs) != 0 {
		t.Errorf("adds and deletes have rewrites: %v", rs)
	}
}

func TestShellPatch(t *testing.T) {
	body := "*** Begin Patch\n*** Add File: a\n+x\n*** End Patch"
	for _, c := range []struct {
		script, dir string
		ok          bool
	}{
		{"apply_patch <<'EOF'\n" + body + "\nEOF\n", "", true},
		{"applypatch <<EOF\n" + body + "\nEOF", "", true},
		{"cd src && apply_patch <<'EOF'\n" + body + "\nEOF\n", "src", true},
		{"cd 'my dir' && apply_patch <<'EOF'\n" + body + "\nEOF\n", "my dir", true},
		{"cd src || apply_patch <<'EOF'\n" + body + "\nEOF\n", "", false},
		{"echo hi; apply_patch <<'EOF'\n" + body + "\nEOF\n", "", false},
		{"apply_patch <<'EOF' && echo done\n" + body + "\nEOF\n", "", false},
		{"cd $D && apply_patch <<'EOF'\n" + body + "\nEOF\n", "", false},
		{"apply_patch x <<'EOF'\n" + body + "\nEOF\n", "", false},
		{"apply_patch < file", "", false},
		{"cat <<'EOF'\n" + body + "\nEOF\n", "", false},
	} {
		patch, dir, ok := ShellPatch(c.script)
		if ok != c.ok || dir != c.dir || ok && patch != body {
			t.Errorf("%q: %q, %q, %v", c.script, patch, dir, ok)
		}
	}
}
