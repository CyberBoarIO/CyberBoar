package shell

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Every name bash expands a glob to is among the paths the analysis
// checks, or the analysis gives up on the glob, in the C locale too.
func TestGlobCoversBash(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses POSIX paths")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not found")
	}
	dir := t.TempDir()
	for _, n := range []string{".env", "token1.txt", "tokenA.txt", "Token2.TXT", "a]b", "x-y", "é.txt", "tokené.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, line := range []string{
		"token[[:digit:]].txt", "token[[:alpha:]].txt", "token[![:digit:]].txt", "token[^0-9].txt",
		"[[:upper:]]oken*", "*[[:punct:]]*", "token[[:digit:][:upper:]].txt", "token[[:alnum:]]*",
		"[.]env", "?env", ".[e]nv", "a[]]b", "x[a-]y", "x[--z]y", "token[[:digit:]",
		"?.txt", "??.txt", "token?.txt", "token??.txt", "*.txt", "[[:alpha:]].txt",
		"shopt -s nocaseglob; cat token[[:digit:]].TXT",
		"shopt -s dotglob; cat [[:punct:]]env",
	} {
		if !strings.Contains(line, ";") {
			line = "cat " + line
		}
		for _, locale := range []string{"C", "C.UTF-8"} {
			t.Run(locale+" "+line, func(t *testing.T) {
				cmd := exec.Command("bash", "--noprofile", "--norc", "-c", strings.Replace(line, "cat ", "printf '%s\\n' ", 1))
				cmd.Dir = dir
				cmd.Env = append(os.Environ(), "LC_ALL="+locale)
				out, err := cmd.Output()
				if err != nil {
					t.Fatal(err)
				}
				an, err := Analyze(line, "/home/dev", dir)
				if err != nil {
					t.Fatal(err)
				}
				checked := map[string]bool{}
				for _, f := range an.Files {
					if !f.Certain {
						return // the analysis gave up on it
					}
					checked[strings.TrimPrefix(f.Path, dir+"/")] = true
				}
				pattern := line[strings.LastIndex(line, " ")+1:]
				for name := range strings.FieldsSeq(string(out)) {
					if name != pattern && !checked[name] {
						t.Errorf("bash matched %q, the analysis checks %v", name, checked)
					}
				}
			})
		}
	}
}

// psWildcardCases are wildcards and names with PowerShell's answer.
var psWildcardCases = []struct {
	pattern, name string
	match         bool
}{
	{"token[!a].txt", "tokena.txt", true},
	{"token[!a].txt", "token!.txt", true},
	{"token[!a].txt", "tokenb.txt", false},
	{"token[^a].txt", "tokena.txt", true},
	{"token[^a].txt", "tokenb.txt", false},
	{"token[a-c].txt", "tokenB.txt", true},
	{"token[a-c].txt", "tokend.txt", false},
	{"token[a`-c].txt", "token-.txt", true},
	{"token[a`-c].txt", "tokenb.txt", false},
	{"token[`]].txt", "token].txt", true},
	{"`*.txt", "*.txt", true},
	{"`*.txt", "a.txt", false},
	{"`.env", ".env", true},
	{"*.E?V", ".env", true},
	{"*a*b", "xaxxb", true},
	{"*a*b", "xaxxbc", false},
	{"?", "", false},
}

// psWildcardRefused are spellings psWildcard refuses as uncertain.
var psWildcardRefused = []string{"a[b", "a[]", "a[]b]", "a[-b]", "a[b-]", "a[c-a]", "a[a-c-e]", "a`"}

// PowerShell's wildcard (about_Wildcards) has sets without negation and `
// escapes; spellings whose meaning isn't certain are refused.
func TestPSWildcard(t *testing.T) {
	for _, c := range psWildcardCases {
		w, err := psWildcard(c.pattern)
		if err != nil {
			t.Errorf("%s: %v", c.pattern, err)
			continue
		}
		if got := psWildcardMatch(w, c.name, true); got != c.match {
			t.Errorf("%s matching %s: got %v, want %v", c.pattern, c.name, got, c.match)
		}
	}
	if w, _ := psWildcard("[a-c]"); psWildcardMatch(w, "B", false) {
		t.Error("[a-c] matched B with case")
	}
	for _, p := range psWildcardRefused {
		if _, err := psWildcard(p); err == nil {
			t.Errorf("%s: no error", p)
		}
	}
}

// PowerShell's own WildcardPattern gives the answers in psWildcardCases, and
// matches nothing psWildcard would miss among the refused spellings' names.
// It needs pwsh and CYBERBOAR_PWSH_DIFF=1 (scripts/pwsh-differential.sh).
func TestPSWildcardDifferential(t *testing.T) {
	if os.Getenv("CYBERBOAR_PWSH_DIFF") != "1" {
		t.Skip("set CYBERBOAR_PWSH_DIFF=1 (scripts/pwsh-differential.sh)")
	}
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell not installed")
	}
	type pair struct{ pattern, name string }
	var pairs []pair
	for _, c := range psWildcardCases {
		pairs = append(pairs, pair{c.pattern, c.name})
	}
	for _, p := range psWildcardRefused {
		for _, n := range []string{"ab", "a]", "a-", "a[b", "a[]", "a]b", "ac", "ad", "a"} {
			pairs = append(pairs, pair{p, n})
		}
	}
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	var script strings.Builder
	script.WriteString("$o = [System.Management.Automation.WildcardOptions]::IgnoreCase\n")
	for _, p := range pairs {
		fmt.Fprintf(&script, "try { [System.Management.Automation.WildcardPattern]::new(%s, $o).IsMatch(%s) } catch { 'error' }\n",
			quote(p.pattern), quote(p.name))
	}
	path := filepath.Join(t.TempDir(), "wildcards.ps1")
	if err := os.WriteFile(path, []byte(script.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-File", path).Output()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(string(out))
	if len(got) != len(pairs) {
		t.Fatalf("%d answers for %d wildcards: %q", len(got), len(pairs), out)
	}
	for i, p := range pairs {
		w, err := psWildcard(p.pattern)
		ours := err == nil && psWildcardMatch(w, p.name, true)
		switch {
		case i < len(psWildcardCases) && !strings.EqualFold(got[i], strconv.FormatBool(psWildcardCases[i].match)):
			t.Errorf("%s matching %q: PowerShell says %s", p.pattern, p.name, got[i])
		case strings.EqualFold(got[i], "true") && err == nil && !ours:
			t.Errorf("%s matches %q in PowerShell, not here", p.pattern, p.name)
		}
	}
}
