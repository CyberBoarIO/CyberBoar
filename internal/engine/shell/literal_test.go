package shell

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// Values are what bash sees; a value that holds quotes or backslashes is
// read again as code (the extra "ab$" and "cd"), which can only add words,
// and printed as printf and echo -e would ("a\bb$")
// Assignments give their value, and so do variables they set; a here-document gives its
// delimiter, not its body
func TestLiteralsWords(t *testing.T) {
	for src, want := range map[string][]string{
		`export GH=gh''p_x "y"z`:                   {"ghp_x", "yz"},
		`echo gh\p_x "a\b\$" 'c\d'`:                {"echo", "ghp_x", `a\b$`, "a\b$", "ab$", `c\d`, "cd"},
		`sh -c "export T=gh''p_x"`:                 {"sh", "-c", "export T=gh''p_x", "ghp_x"},
		`cat > out <<EOF` + "\nx''y\nEOF":          {"cat", "out", "EOF"},
		`echo $X "a$Y" $(echo q''r) {1..99999999}`: {"echo", "a", "echo", "qr", "{1..99999999}"},
		`echo 'unterminated`:                       nil,
		"echo a\\\nb":                              {"echo", "ab"},
		`A=gh B=p_x; echo "$A${B}" $A$C`:           {"gh", "p_x", "echo", "ghp_x", "gh"},
		`A=gh; A+=p_x; echo $A`:                    {"gh", "p_x", "echo", "ghp_x"},
		`echo $'\x67h\160_x' $'\u0067'`:            {"echo", "ghp_x", "g"},
		`printf '\x67\150p_x' 'a\0147'`:            {"printf", `\x67\150p_x`, "ghp_x", `g\150p_x`, "x67150p_x", `a\0147`, "a\f7", "ag", "a0147"},
		`echo $'\501' $'\U110000x\UFFFFFFFFy'`:     {"echo", "A", "xy"}, // the low byte; past MaxRune is dropped
		`echo ${A:-x} ${#A} ${A/a/b}`:              {"echo", "x", "a", "b"},
	} {
		got, _, err := Literals(src)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, want) {
			t.Errorf("Literals(%q) words = %q, want %q", src, got, want)
		}
	}
	if words, args, err := Literals(strings.Repeat("a ", maxLiteralWords+10)); !errors.Is(err, ErrTooComplex) || words != nil || args != "" {
		t.Errorf("word limit: words=%d, args=%d bytes, error=%v", len(words), len(args), err)
	}
}

// Arguments run together are what printf %s%s, or echo -n in turn, print;
// options and redirection targets are left out
func TestLiteralsArgs(t *testing.T) {
	for src, want := range map[string]string{
		`printf %s%s gh p_x > out`:           "%s%sghp_x",
		`echo -n gh > t; echo -n p_x >> t`:   "ghp_x",
		`A=p_x; echo -e gh"$A" | tee -a log`: "ghp_xlog",
		`cat <<EOF` + "\nbody\nEOF":          "",
		`x $(echo in) after`:                 "afterin", // the outer command first
	} {
		if _, got, err := Literals(src); err != nil || got != want {
			t.Errorf("Literals(%q) args = %q, want %q", src, got, want)
		}
	}
}

func TestLiteralsExpansionLimits(t *testing.T) {
	for _, tc := range []struct {
		name, src string
	}{
		{"doubling", "A=x;" + strings.Repeat("A=$A$A;", 20) + "echo $A"},
		{"appending", "A=x;" + strings.Repeat("A+=$A;", 20) + "echo $A"},
		{"aggregate", "A=" + strings.Repeat("x", 1000) + ";echo " + strings.Repeat("$A ", 2000)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			words, args, err := Literals(tc.src)
			if !errors.Is(err, ErrTooLarge) || words != nil || args != "" {
				t.Fatalf("want no partial output and ErrTooLarge, got %d words, %d argument bytes, %v", len(words), len(args), err)
			}
		})
	}
}

// The last accepted byte fits; the next byte is refused before it is appended
func TestLiteralsByteBudgetBoundary(t *testing.T) {
	l := literals{}
	var b strings.Builder
	l.write(&b, strings.Repeat("x", maxLiteralBytes-1))
	l.write(&b, "y")
	if l.err != nil || b.Len() != maxLiteralBytes {
		t.Fatalf("at limit: bytes=%d, error=%v", b.Len(), l.err)
	}
	l.write(&b, "z")
	if !errors.Is(l.err, ErrTooLarge) || b.Len() != maxLiteralBytes {
		t.Fatalf("past limit: bytes=%d, error=%v", b.Len(), l.err)
	}
}

func FuzzLiterals(f *testing.F) {
	for _, src := range []string{
		`A=gh; B=p_x; printf %s%s "$A" "$B"`,
		"A=x;" + strings.Repeat("A=$A$A;", 20) + "echo $A",
		"echo " + strings.Repeat("x ", maxLiteralWords+1),
		`sh -c 'printf "a\\b"'`,
	} {
		f.Add(src)
	}
	f.Fuzz(func(t *testing.T, src string) {
		words, args, err := Literals(src)
		if err != nil {
			if !errors.Is(err, ErrTooLarge) && !errors.Is(err, ErrTooComplex) {
				t.Fatalf("unexpected error: %v", err)
			}
			if words != nil || args != "" {
				t.Fatal("limit failure returned partial text")
			}
			return
		}
		total := len(args)
		for _, word := range words {
			total += len(word) + 1
		}
		if len(words) > maxLiteralWords || total > maxLiteralBytes {
			t.Fatalf("unbounded output: %d words, %d bytes", len(words), total)
		}
	})
}
