package shell

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Every name bash expands a glob to is among the paths the analysis
// checks, or the analysis gives up on the glob, in the C locale too
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
				for _, name := range strings.Fields(string(out)) {
					if name != pattern && !checked[name] {
						t.Errorf("bash matched %q, the analysis checks %v", name, checked)
					}
				}
			})
		}
	}
}
