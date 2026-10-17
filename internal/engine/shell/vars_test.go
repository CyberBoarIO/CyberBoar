package shell_test

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/engine/shell"
)

// lastArgs returns the argv of the last command as written, with "?" for a
// word only known at run time
func lastArgs(t *testing.T, src string, persistent bool) []string {
	t.Helper()
	an, err := shell.AnalyzeWith(src, "/home/u", shell.Options{Cwd: "/w", Persistent: persistent})
	if err != nil {
		t.Fatalf("%q: %v", src, err)
	}
	if len(an.Commands) == 0 {
		t.Fatalf("%q: no commands", src)
	}
	var out []string
	for _, e := range an.Commands[len(an.Commands)-1].Layers[0] {
		if e.Kind == shell.Lit {
			out = append(out, e.Text)
		} else {
			out = append(out, "?")
		}
	}
	return out
}

// A variable the line sets itself is known where nothing can have changed it
func TestLineVars(t *testing.T) {
	for _, c := range []struct {
		src  string
		want string // the last command's argv, words joined by " "
	}{
		{`f=/x/a.txt; cat "$f"`, "cat /x/a.txt"},
		{`C=/x; wc -l $C/notes.txt`, "wc -l /x/notes.txt"},
		{`C=/x; cat "${C}"`, "cat /x"},
		{`C=/x && cat "$C/a"`, "cat /x/a"},
		{`C=/x && make && cat "$C"`, "cat /x"},
		{`D=src; F="$D/main.go"; cat "$F"`, "cat src/main.go"},
		{`A=1 B=$A; cat "$B"`, "cat 1"},
		{`C='a b'; cat "$C"`, "cat a b"},
		{`C=~/x; cat "$C"`, "cat /home/u/x"},
		{`C=/x; printf '%s' "$C"`, "printf %s /x"},
		{`C=/x; printf -- '%s' "$C"`, "printf -- %s /x"},
		{`C=/x; command -v ls; cat "$C"`, "cat /x"},
		{`C=/x; for f in a; do cat "$C"; done`, "cat /x"},
		{`C=/x; export D=1; cat "$C"`, "cat /x"},

		// Not known
		{`make && C=/x; cat "$C"`, "cat ?"},   // the assignment may not run
		{`C=/x || :; cat "$C"`, "cat ?"},      // not a plain statement
		{`cat "$C"; C=/x`, "cat ?"},           // used before it is set
		{`C=/x cat "$C"`, "cat ?"},            // a prefix assignment expands the old value
		{`C=/x; C=/y; cat "$C"`, "cat ?"},     // written twice
		{`C=/x; (C=/y); cat "$C"`, "cat ?"},   // written twice, once in a subshell
		{`C=/x; export C; cat "$C"`, "cat ?"}, // declared too
		{`C=/x; read C; cat "$C"`, "cat ?"},   // read assigns
		{`C=/x; command read C; cat "$C"`, "cat ?"},
		{`C=/x; printf -v C %s y; cat "$C"`, "cat ?"},
		{`C=/x; wait -p C; cat "$C"`, "cat ?"},
		{`C=/x; f() { :; }; cat "$C"`, "cat ?"}, // a function may assign
		{`C=/x; eval :; cat "$C"`, "cat ?"},
		{`C=/x; source /dev/null; cat "$C"`, "cat ?"},
		{`C=/x; . /dev/null; cat "$C"`, "cat ?"},
		{`C=/x; alias x=y; cat "$C"`, "cat ?"},
		{`C=/x; trap : DEBUG; cat "$C"`, "cat ?"},
		{`C=/x; declare -n R=C; cat "$C"`, "cat ?"},
		{`C=/x; local D; cat "$C"`, "cat ?"},
		{`C=/x; (( D=1 )); cat "$C"`, "cat ?"},
		{`C=/x; echo $((D++)); cat "$C"`, "cat ?"},
		{`C=/x; let D=1; cat "$C"`, "cat ?"},
		{`C=/x; : ${C:=/y}; cat "$C"`, "cat ?"},
		{`C=/x; for C in a; do :; done; cat "$C"`, "cat ?"},
		{`C=/x; exec {D}>/dev/null; cat "$C"`, "cat ?"},
		{`C=/x; $CMD; cat "$C"`, "cat ?"}, // could be read
		{`C=/x; printf "$F" y; cat "$C"`, "cat ?"},
		{`C=/x & cat "$C"`, "cat ?"},    // a background job is a subshell
		{`C=/x | :; cat "$C"`, "cat ?"}, // a pipeline is a subshell
		{`! C=/x; cat "$C"`, "cat ?"},
		{`C=/x 2>/dev/null; cat "$C"`, "cat ?"},
		{`C=$(pwd); cat "$C"`, "cat ?"},
		{`C=*.go; cat "$C"`, "cat ?"},
		{`C=a:~/x; cat "$C"`, "cat ?"},
		{`C+=/x; cat "$C"`, "cat ?"},
		{`C=(a b); cat "$C"`, "cat ?"},
		{`PATH=/x; cat "$PATH"`, "cat ?"},
		{`IFS=/; cat "$IFS"`, "cat ?"},
		{`C='a b'; cat $C`, "cat ?"},      // split unquoted
		{`C=\*; cat $C`, "cat ?"},         // globbed unquoted
		{`IFS=/; C=x; cat $C`, "cat ?"},   // IFS assigned: unquoted is unknown
		{`IFS=/; C=x; cat "$C"`, "cat x"}, // quoted is not split

		// Arithmetic evaluates the values of the names it reads, so any of it
		// may assign: [[ -eq ]], (( )), $(( )), for (( )), indexes and slices
		{`C=/x; [[ 1 -eq C=0 ]]; cat "$C"`, "cat ?"},
		{`C=/x; X='C=0'; (( X )); cat "$C"`, "cat ?"},
		{`C=/x; echo $(( X )); cat "$C"`, "cat ?"},
		{`C=/x; for ((i = 0; i < 1; i++)); do :; done; cat "$C"`, "cat ?"},
		{`C=/x; : "${A[X]}"; cat "$C"`, "cat ?"},
		{`C=/x; : "${A:X}"; cat "$C"`, "cat ?"},
		{`C=/x; [[ -f a && $X == b ]]; cat "$C"`, "cat /x"}, // string tests aren't arithmetic

		// Options that assign, in clusters and after other options' arguments
		{`C=/x; wait -np C; cat "$C"`, "cat ?"},
		{`C=/x; printf -vC %s y; cat "$C"`, "cat ?"},
		{`C=/x; print -v C y; cat "$C"`, "cat ?"},
		{`C=/x; print -C 3 -v C y; cat "$C"`, "cat ?"},
		{`C=/x; command -- read C; cat "$C"`, "cat ?"},
		{`C=/x; builtin -- printf -v C y; cat "$C"`, "cat ?"},
		{`C=/x; wait -n; cat "$C"`, "cat /x"},
		{`C=/x; print -- -v; cat "$C"`, "cat /x"},
	} {
		got := strings.Join(lastArgs(t, c.src, false), " ")
		if got != c.want {
			t.Errorf("%q: got %q, want %q", c.src, got, c.want)
		}
	}
}

// A shell that persists between commands may have an alias or a DEBUG trap
// from an earlier command that assigns the name
func TestLineVarsPersistent(t *testing.T) {
	if got := lastArgs(t, `C=/x; cat "$C"`, true); !slices.Equal(got, []string{"cat", "?"}) {
		t.Errorf("got %q", got)
	}
}

// Code a nested shell runs doesn't see the line's unexported variables, but
// a double-quoted argument is expanded before it gets there
func TestLineVarsNested(t *testing.T) {
	an, err := shell.Analyze(`C=/x; bash -c "cat $C/a"; bash -c 'cat $C/b'`, "/home/u", "/w")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range an.Commands {
		var words []string
		for _, e := range c.Layers[0] {
			words = append(words, e.String())
		}
		got = append(got, strings.Join(words, " "))
	}
	for _, want := range []string{"cat /x/a", "cat …"} {
		if !slices.Contains(got, want) {
			t.Errorf("commands %q lack %q", got, want)
		}
	}
}

// Every value the analysis claims to know is the one bash and zsh print
// The lines only assign and run printf
func TestLineVarsMatchShells(t *testing.T) {
	lines := []string{
		`C=/x; printf '<%s>' "$C"`,
		`C=/x; printf '<%s>' $C`,
		`C='a b'; printf '<%s>' "$C"`,
		`C='a b'; printf '<%s>' $C`,
		`C=/x/y; D="$C/z"; printf '<%s>' "$D" $D`,
		`A=1 B=$A; printf '<%s>' "$B"`,
		`C=; printf '<%s>' "$C" x`,
		`C=~/x; printf '<%s>' "$C"`,
		`C=x && printf '<%s>' "$C"`,
		`C='$HOME'; printf '<%s>' "$C" $C`,
		`C=\*; printf '<%s>' "$C" $C`,
		`C="x y"; printf '<%s>' "${C}"`,
		`C=/x; C2=$C$C; printf '<%s>' "$C2"`,
		`C=a\ b; printf '<%s>' "$C"`,
		`C=$'a\tb'; printf '<%s>' "$C"`,
		`C="$HOME/x"; printf '<%s>' "$C"`,
		`C={a,b}; printf '<%s>' "$C"`,
		`C=a=b; printf '<%s>' "$C" $C`,
		`C=-n; printf '<%s>' "$C" $C`,
		`C=/x; printf '<%s>' "$C"{,}`,
		`C=/x; printf '<%s>' "$C/"*`,
		`C=a; printf '<%s>' "${C}b" $C.c`,
		`C="'q'"; printf '<%s>' "$C" $C`,
		`C=x; D="$C"; C2="$D"; printf '<%s>' "$C2"`,
	}
	home := t.TempDir()
	known := 0
	for _, sh := range [][]string{{"bash", "--norc", "--noprofile", "-c"}, {"zsh", "-f", "-c"}} {
		path, err := exec.LookPath(sh[0])
		if err != nil {
			t.Logf("%s not installed", sh[0])
			continue
		}
		for _, src := range lines {
			an, err := shell.Analyze(src, home, home)
			if err != nil {
				t.Fatalf("%q: %v", src, err)
			}
			last := an.Commands[len(an.Commands)-1].Layers[0]
			var want []string
			for _, e := range last[2:] { // printf '<%s>'
				if e.Kind != shell.Lit {
					want = nil
					break
				}
				want = append(want, "<"+e.Text+">")
			}
			if want == nil && len(last) > 2 {
				continue // not claimed known
			}
			known++
			cmd := exec.Command(path, append(sh[1:], src)...)
			cmd.Dir = home
			cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
			out, err := cmd.Output()
			if err != nil {
				t.Errorf("%s %q: %v", sh[0], src, err)
				continue
			}
			if got := string(out); got != strings.Join(want, "") {
				t.Errorf("%s %q: prints %q, the analysis claims %q", sh[0], src, got, strings.Join(want, ""))
			}
		}
	}
	t.Logf("compared %d claimed values with the shells", known)
	if known == 0 && os.Getenv("CI") != "" {
		t.Error("no shell to compare with")
	}
}
