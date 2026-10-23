package shell

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/engine/osfs"
)

// psCorpus returns the parser's differential inputs (pwsh/testdata/differential)
func psCorpus(tb testing.TB) []string {
	files, err := filepath.Glob(filepath.Join("pwsh", "testdata", "differential", "*.txt"))
	if err != nil || len(files) == 0 {
		tb.Fatalf("no corpus: %v", err)
	}
	var out []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			tb.Fatal(err)
		}
		for _, in := range strings.Split(string(b), "\n---\n") {
			if !strings.HasPrefix(in, "#") {
				out = append(out, strings.TrimSuffix(in, "\n---"))
			}
		}
	}
	return out
}

// AnalyzePowerShell fails closed on anything: it never panics, and an error
// is one the engine denies. On Windows and elsewhere
func checkPowerShell(t *testing.T, in string) {
	for _, o := range []Options{{Cwd: "/c/work", FS: osfs.FS{Windows: true}}, {Cwd: "/work"}, {CwdUnknown: true, Persistent: true}} {
		an, err := AnalyzePowerShell(in, "/c/Users/dev", o)
		if err != nil {
			if !errors.Is(err, ErrUnparseable) && !errors.Is(err, ErrTooLarge) && !errors.Is(err, ErrTooComplex) {
				t.Fatalf("%q: error %T %v", in, err, err)
			}
			continue
		}
		for _, c := range an.Commands {
			if len(c.Layers) == 0 {
				t.Fatalf("%q: a command without layers", in)
			}
		}
		for i := range an.Commands {
			an.Feeds(i, i)
		}
	}
}

func TestPowerShellCorpus(t *testing.T) {
	for _, in := range psCorpus(t) {
		checkPowerShell(t, in)
	}
}

func FuzzAnalyzePowerShell(f *testing.F) {
	for _, in := range psCorpus(f) {
		f.Add(in)
	}
	f.Fuzz(checkPowerShell)
}
