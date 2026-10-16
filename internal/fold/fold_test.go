package fold_test

import (
	"testing"

	"cyberboar.dev/cyberboar/internal/fold"
)

func TestString(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{".ENV", ".env"},
		{".e\u200Cnv", ".env"},               // zero-width non-joiner (HFS+ ignores it)
		{".e\u200Dnv", ".env"},               // zero-width joiner
		{".ssh\uFEFF", ".ssh"},               // byte order mark
		{"cred\u202Eentials", "credentials"}, // right-to-left override
		{"a\u00ADb", "ab"},                   // soft hyphen
		{"a\uFE0Fb", "ab"},                   // variation selector
		{".\u017Fsh", ".ssh"},                // long s: full case folding
		{".\u212Aube", ".kube"},              // Kelvin sign
		{"cle\u0301s", "cl\u00E9s"},          // NFD and NFC agree
		{"CLE\u0301S", "cl\u00E9s"},
		{"cl\u00C9s", "cl\u00E9s"},
		{"\u13B7\uAB87", "\uAB87\uAB87"}, // Cherokee upper and lower case are one letter
		{"**/*.[Pp]em", "**/*.[pp]em"},   // glob syntax is ASCII and survives
		{"\\*x", "\\*x"},
	} {
		if got := fold.String(tc.in); got != tc.want {
			t.Errorf("String(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestInvalidUTF8BeforeComposedUnicode(t *testing.T) {
	// The full CI fuzzer found that normalization stopped at the invalid
	// prefix, leaving the composed Greek rune to change on the next fold
	input := "\xf2\u03af"
	once := fold.String(input)
	if twice := fold.String(once); twice != once {
		t.Fatalf("not idempotent: %q -> %q -> %q", input, once, twice)
	}
	if decomposed := fold.String("\xf2\u03b9\u0301"); decomposed != once {
		t.Fatalf("canonical spellings differ: %q and %q", once, decomposed)
	}
}

// Folding is idempotent and never turns a non-ASCII rune into glob syntax
func FuzzString(f *testing.F) {
	for _, s := range []string{".e\u200Cnv", "CLE\u0301S", "\u017F\u212A", "a*b?[c]{d}\\e", "\xff\xfe", "\xf2\u03af"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		once := fold.String(s)
		if twice := fold.String(once); twice != once {
			t.Fatalf("not idempotent: %q -> %q -> %q", s, once, twice)
		}
		count := func(x string) (n int) {
			for _, r := range x {
				switch r {
				case '*', '?', '[', ']', '{', '}', '\\', '/', ',':
					n++
				}
			}
			return n
		}
		if count(once) != count(s) {
			t.Fatalf("glob syntax changed: %q -> %q", s, once)
		}
	})
}

func BenchmarkString(b *testing.B) {
	for _, s := range []string{"home/dev/repo/internal/engine/files.go", "home/dev/repo/docs/clés/prod.key"} {
		b.Run(s[len(s)-8:], func(b *testing.B) {
			for b.Loop() {
				fold.String(s)
			}
		})
	}
}
