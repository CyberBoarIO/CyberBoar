package shell_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"cyberboar.dev/cyberboar/internal/corpustest"
	"cyberboar.dev/cyberboar/internal/engine/shell"
)

const corpusDir = "../../../testdata/corpus"

// TestBashDifferential compares how the analyzer (mvdan.cc/sh) and real bash
// parse every shell command in the corpus, since syntax both accept but read
// differently is a potential bypass. Bash never runs the commands: each one
// becomes the body of a function, and `declare -f` prints bash's own reading
// of it. Analysing that reprint must give the same commands and paths as
// analysing the original; a difference means bash reads the command line
// differently.
//
// Only what bash's reading has and the analyzer's lacks is an error (a
// potential bypass); the reverse is over-approximation and only logged. It
// needs bash and CYBERBOAR_BASH_DIFF=1 (scripts/bash-differential.sh).
// Containment, should bash ever end the function early and reach top-level
// code: a DEBUG trap (extdebug) aborts before any simple command, PATH is
// empty, kill is disabled, noclobber and `ulimit -f 0` stop file writes, the
// working directory and HOME are a temp dir, and inputs that redirect to
// absolute paths are skipped.
func TestBashDifferential(t *testing.T) {
	if os.Getenv("CYBERBOAR_BASH_DIFF") != "1" {
		t.Skip("set CYBERBOAR_BASH_DIFF=1 (scripts/bash-differential.sh)")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	inputs := differentialInputs(t)

	work := t.TempDir()
	var compared, skipped, rejected, overApprox int
	var diffs []string
	for _, in := range slices.Sorted(mapKeys(inputs)) {
		switch outcome, detail := compareWithBash(t, bash, nil, work, in); outcome {
		case skippedInput:
			skipped++
		case rejectedByBash:
			rejected++
		case differs:
			diffs = append(diffs, detail)
		case overApproximated:
			compared++
			overApprox++
			t.Logf("over-approximation (safe): %q: %s", in, detail)
		default:
			compared++
		}
	}
	t.Logf("compared %d command lines with bash (%d over-approximated); %d rejected by bash, %d skipped",
		compared, overApprox, rejected, skipped)
	for _, d := range diffs {
		t.Errorf("parser differential: %s", d)
	}
}

type outcome int

const (
	same outcome = iota
	overApproximated
	skippedInput
	rejectedByBash
	differs
)

// compareWithBash analyses in and bash's reprint of it. wrap, if set, is the
// command that bash runs under (a sandbox).
func compareWithBash(t *testing.T, bash string, wrap []string, work, in string) (outcome, string) {
	const root = "/nonexistent/cbdiff"
	home, cwd := root+"/home", root+"/repo"
	if unsafeForBash(in) {
		return skippedInput, ""
	}
	orig, err := shell.Analyze(in, home, cwd)
	if err != nil {
		return skippedInput, "" // the engine denies what it can't parse
	}
	body, ok := bashReprint(t, bash, wrap, work, in)
	if !ok {
		return rejectedByBash, "" // bash won't run it as a function body; nothing to compare
	}
	if !utf8.ValidString(body) {
		// Escapes gave bytes that aren't UTF-8; the parser only reads UTF-8,
		// so bash's reprint can't be compared (the original was analyzed)
		return rejectedByBash, ""
	}
	if !strings.Contains(in, "COPROC") {
		body = coprocDefaultName.ReplaceAllString(body, "${1}coproc ")
	}
	re, err := shell.Analyze(body, home, cwd)
	if err != nil {
		return differs, fmt.Sprintf("%q\n  bash reads it as %q, which doesn't parse: %v", in, body, err)
	}
	a, b := summary(orig), summary(re)
	if missing := uncovered(orig, re); missing != "" && shell.ShellDependent(in) {
		// The analyzer deliberately doesn't pick bash's reading of an escape
		// (a run-time word): what bash derives from it can differ
		return overApproximated, missing
	} else if missing != "" {
		// Bash sees something the analyzer doesn't: a potential bypass
		return differs, fmt.Sprintf("%q\n  bash reprint: %q\n  missed by the analyzer: %q", in, body, missing)
	}
	if extra := a.notIn(b); extra != "" {
		return overApproximated, extra // the analyzer sees more than bash would run: stricter, fine
	}
	return same, ""
}

// differentialInputs is every shell command line in the corpus and in
// testdata/differential of this package.
func differentialInputs(t *testing.T) map[string]bool {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(corpusDir, "*.yaml"))
	extra, _ := filepath.Glob(filepath.Join("testdata", "differential", "*.txt"))
	const root = "/nonexistent/cbdiff"
	inputs := map[string]bool{}
	for _, path := range files {
		f, err := corpustest.LoadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range f.Cases {
			a, err := f.Action(c, root)
			if err == nil && a.Tool == "shell" && a.Command != "" {
				inputs[a.Command] = true
			}
		}
	}
	for _, path := range extra {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for block := range strings.SplitSeq(string(data), "\n---\n") {
			if block = strings.Trim(block, "\n"); block != "" && !strings.HasPrefix(block, "#") {
				inputs[block] = true
			}
		}
	}
	return inputs
}

func mapKeys(m map[string]bool) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// coprocDefaultName finds bash's reprint of a coprocess running a simple
// command: bash up to 5.2 prints the default name, `coproc COPROC cat .env`,
// which bash itself would read as the command COPROC. Undone unless the input
// names COPROC itself, so a real `coproc COPROC cmd` is still compared.
var coprocDefaultName = regexp.MustCompile(`(^|[\s;&|(])coproc COPROC `)

// absRedirect finds redirections to paths outside the temp dir.
var absRedirect = regexp.MustCompile(`[<>]\|?\s*["']?[/~$]`)

func unsafeForBash(s string) bool {
	return absRedirect.MatchString(s) || strings.Contains(s, "enable") || strings.ContainsRune(s, 0)
}

// bashReprint returns bash's reprint of s as a function body.
func bashReprint(t *testing.T, bash string, wrap []string, dir, s string) (string, bool) {
	script := "set -o noclobber\nulimit -f 0\nenable -n kill\nshopt -s extdebug\n" +
		`trap '[[ $BASH_COMMAND == "declare -f f" ]] || exit 99' DEBUG` + "\nf() {\n" + s + "\n}\ndeclare -f f\n"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	argv := append(slices.Clone(wrap), bash, "--norc", "--noprofile", "-c", script)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/nonexistent", "HOME=" + dir, "LC_ALL=C"}
	cmd.Stdin = nil
	cmd.WaitDelay = time.Second // a stray child must not keep the pipe open
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	text := string(out)
	start := strings.Index(text, "\n{ \n")
	end := strings.LastIndex(text, "\n}")
	if !strings.HasPrefix(text, "f () ") || start < 0 || end <= start {
		t.Fatalf("unexpected declare -f output for %q: %q", s, text)
	}
	return text[start+4 : end], true
}

// found is what an analysis found, as sets of stable strings.
type found struct{ cmds, files, code []string }

// notIn lists what f has that g doesn't.
func (f found) notIn(g found) string {
	var out []string
	for _, pair := range [][2][]string{{f.cmds, g.cmds}, {f.files, g.files}, {f.code, g.code}} {
		for _, x := range pair[0] {
			if !slices.Contains(pair[1], x) {
				out = append(out, x)
			}
		}
	}
	return strings.Join(out, "; ")
}

// uncovered lists what bash's reading (re) has that the analyzer's (orig)
// doesn't cover.
// A run-time element or path in orig covers what bash would make of it: the analyzer checks it as any value of its shape.
func uncovered(orig, re *shell.Analysis) string {
	var out []string
	a, b := summary(orig), summary(re)
	for i, c := range re.Commands {
		if slices.Contains(a.cmds, b.cmds[i]) {
			continue
		}
		if !slices.ContainsFunc(orig.Commands, func(o shell.Command) bool { return coversCommand(o, c) }) {
			out = append(out, b.cmds[i])
		}
	}
	for i, r := range re.Files {
		if slices.Contains(a.files, b.files[i]) {
			continue
		}
		if !slices.ContainsFunc(orig.Files, func(o shell.FileRef) bool {
			return !o.Certain && o.Rel == "" && (o.Accessed || !r.Accessed) && (o.Contents || !r.Contents)
		}) {
			out = append(out, b.files[i])
		}
	}
	for i := range re.Code {
		if !slices.Contains(a.code, b.code[i]) {
			out = append(out, b.code[i])
		}
	}
	return strings.Join(out, "; ")
}

func coversCommand(o, c shell.Command) bool {
	if len(o.Layers) != len(c.Layers) {
		return false
	}
	for i := range o.Layers {
		if !coversElems(o.Layers[i], c.Layers[i]) {
			return false
		}
	}
	return true
}

// coversElems reports whether the elements o could be the elements c: a
// literal is itself, One is one word of its shape, Many any number of them.
func coversElems(o, c []shell.Elem) bool {
	if len(o) == 0 {
		return len(c) == 0
	}
	switch e := o[0]; e.Kind {
	case shell.Many:
		for n := 0; n <= len(c); n++ {
			if (n == 0 || shapeMatches(e.Text, c[n-1])) && coversElems(o[1:], c[n:]) {
				return true
			}
			if n < len(c) && !shapeMatches(e.Text, c[n]) {
				return false
			}
		}
		return false
	case shell.One:
		return len(c) > 0 && shapeMatches(e.Text, c[0]) && coversElems(o[1:], c[1:])
	default:
		return len(c) > 0 && c[0] == e && coversElems(o[1:], c[1:])
	}
}

// shapeMatches reports whether an element fits a run-time shape, a glob
// whose * matches anything (slashes too).
func shapeMatches(shape string, e shell.Elem) bool {
	re := "^" + strings.ReplaceAll(strings.ReplaceAll(regexp.QuoteMeta(shape), `\*`, ".*"), `\?`, ".") + "$"
	return regexp.MustCompile(re).MatchString(e.Text)
}

// summary is what the analysis found.
func summary(an *shell.Analysis) found {
	var f found
	for _, c := range an.Commands {
		var layers []string
		for _, l := range c.Layers {
			parts := make([]string, len(l))
			for i, e := range l {
				parts[i] = fmt.Sprintf("%d:%s", e.Kind, e.Text)
			}
			layers = append(layers, strings.Join(parts, " "))
		}
		f.cmds = append(f.cmds, strings.Join(layers, " > "))
	}
	for _, r := range an.Files {
		f.files = append(f.files, fmt.Sprintf("%s|%s|%v|%s|%v|%v", r.Path, r.Display, r.Certain, r.Rel, r.Accessed, r.Contents))
	}
	for _, c := range an.Code {
		f.code = append(f.code, fmt.Sprintf("%s|%v", c.What, c.Analyzed))
	}
	return f
}
