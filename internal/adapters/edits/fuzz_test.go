package edits

import (
	"testing"

	"cyberboar.dev/cyberboar/internal/secrets"
)

// FuzzPatch parses arbitrary documents and applies valid updates without panicking.
// A successful rewrite must return at least one result.
func FuzzPatch(f *testing.F) {
	f.Add(patch("*** Update File: f\n@@ ctx\n a\n-b\n+c\n*** End of File\n"), "ctx\na\nb\n")
	f.Add(patch("*** Update File: f\n*** Move to: g\n@@\n+x\n@@\n-–\n"), "—\n")
	f.Add("<<'EOF'\n"+patch("*** Add File: f\n+x\n")+"EOF", "")
	f.Fuzz(func(t *testing.T, doc, old string) {
		rs, err := Patch(doc)
		if err != nil {
			return
		}
		for _, r := range rs {
			out, err := r(old, true)
			if err == nil && len(out) == 0 {
				t.Fatal("no result and no error")
			}
		}
	})
}

// FuzzStrings applies any edit to any file with either matching: no panic, and a result or an error.
func FuzzStrings(f *testing.F) {
	f.Add("x =   1\n", "x = 1", "y", false)
	f.Add("“a”\t–\n", `"a" -`, "", true)
	f.Add("a\xffb", "\xff", "c", false)
	f.Fuzz(func(t *testing.T, old, find, with string, all bool) {
		for _, m := range []Matching{Loose, Opencode} {
			out, err := StringsMatching([]Replace{{Old: find, New: with, All: all}}, m)(old, true)
			if err == nil && (len(out) == 0 || len(out) > maxResults) {
				t.Fatalf("matching %d: %d results", m, len(out))
			}
			for _, o := range out {
				if len(o) > secrets.MaxText {
					t.Fatalf("matching %d: result exceeds secret scan limit: %d bytes", m, len(o))
				}
				if find != "" && with == "" && len(o) > len(old) {
					t.Fatalf("matching %d: deleting grew the file: %q", m, o)
				}
			}
		}
	})
}
