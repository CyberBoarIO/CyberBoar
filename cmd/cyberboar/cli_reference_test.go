package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/pkg/brand"
)

const cliReference = "../../docs/cli.md"

func TestReferenceCommandExamples(t *testing.T) {
	data, err := os.ReadFile(cliReference)
	if err != nil {
		t.Fatal(err)
	}
	_, examples, ok := strings.Cut(string(data), "## Command examples\n")
	if !ok {
		t.Fatal("CLI reference has no command examples")
	}
	headings := regexp.MustCompile("(?m)^### `([a-z]+)`$").FindAllStringSubmatchIndex(examples, -1)
	sections := map[string]string{}
	for i, h := range headings {
		end := len(examples)
		if i+1 < len(headings) {
			end = headings[i+1][0]
		}
		name := examples[h[2]:h[3]]
		if _, exists := sections[name]; exists {
			t.Errorf("duplicate command example: %s", name)
		}
		sections[name] = examples[h[1]:end]
	}
	for _, name := range append(usageCommands(), "help") {
		section, exists := sections[name]
		if !exists {
			t.Errorf("missing command example: %s", name)
			continue
		}
		if !strings.Contains(section, "```sh\n") || !strings.Contains(section, brand.Name+" "+name) {
			t.Errorf("%s example has no command block", name)
		}
		if !strings.Contains(section, "```text\n") && !strings.Contains(section, "```json\n") {
			t.Errorf("%s example has no response block", name)
		}
		if !strings.Contains(section, "exit `") {
			t.Errorf("%s example has no exit status", name)
		}
	}
}

// refFlag is one row of a command's flag table in docs/cli.md
type refFlag struct {
	value, env, def string
}

// readReference returns the flag tables of docs/cli.md by command, and the
// variables its Environment table lists
func readReference(t *testing.T) (map[string]map[string]refFlag, []string) {
	t.Helper()
	data, err := os.ReadFile(cliReference)
	if err != nil {
		t.Fatal(err)
	}
	heading := regexp.MustCompile("^## `" + brand.Name + " ([a-z]+)`$")
	flagCell := regexp.MustCompile("^`--?([a-z-]+)(?: ([^`]+))?`$")
	envCell := regexp.MustCompile("^`(" + brand.EnvPrefix + "[A-Z_]+)`$")
	commands := map[string]map[string]refFlag{}
	var env []string
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "## ") {
			section = line
			if m := heading.FindStringSubmatch(line); m != nil {
				section = m[1]
				if commands[section] != nil {
					t.Errorf("%s: two sections for %s", cliReference, section)
				}
				commands[section] = map[string]refFlag{}
			}
			continue
		}
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), " | ")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		switch {
		case section == "## Environment":
			if m := envCell.FindStringSubmatch(cells[0]); m != nil {
				env = append(env, m[1])
			}
		case commands[section] != nil && strings.HasPrefix(line, "| `-"):
			m := flagCell.FindStringSubmatch(cells[0])
			if m == nil || len(cells) != 4 {
				t.Errorf("%s: %s: malformed flag row %q", cliReference, section, line)
				continue
			}
			if _, dup := commands[section][m[1]]; dup {
				t.Errorf("%s: %s: --%s listed twice", cliReference, section, m[1])
			}
			commands[section][m[1]] = refFlag{value: m[2], env: cells[1], def: cells[2]}
		}
	}
	return commands, env
}

// usageCommands are the commands `cyberboar help` lists
func usageCommands() []string {
	var b bytes.Buffer
	usage(&b)
	var out []string
	for _, m := range regexp.MustCompile(`(?m)^  ([a-z]+)  `).FindAllStringSubmatch(b.String(), -1) {
		out = append(out, m[1])
	}
	return out
}

// commandFlags runs `cyberboar COMMAND --help` and returns the flag set the
// command defined, nil for a command without flags
func commandFlags(t *testing.T, command string, getenv func(string) string) *flag.FlagSet {
	t.Helper()
	c, ok := commands[command]
	if !ok {
		return nil
	}
	fs := commandFlagSet(command)
	var out, errb bytes.Buffer
	c(host{getenv: getenv, goos: runtime.GOOS, now: time.Now}, fs, []string{"--help"}, strings.NewReader(""), &out, &errb)
	return fs
}

// TestCLIReference holds the CLI to its frozen reference, docs/cli.md: the
// same commands, and for each the same flags with the same kind of value,
// environment variable and default. A change to either needs the other in the
// same commit
func TestCLIReference(t *testing.T) {
	ref, refEnv := readReference(t)
	commands := usageCommands()
	if len(commands) < 10 {
		t.Fatalf("found only %d commands in the usage text: %v", len(commands), commands)
	}
	listed := map[string]bool{}
	for _, c := range commands {
		listed[c] = true
		if ref[c] == nil {
			t.Errorf("%s has no section for %q", cliReference, c)
		}
	}
	for c := range ref {
		if !listed[c] {
			t.Errorf("%s documents %q, which the usage text doesn't list", cliReference, c)
		}
	}

	// Each variable answers with its own name, so a flag's default shows which one it falls back to
	named := func(k string) string { return "$" + k }
	empty := func(string) string { return "" }
	for _, c := range commands {
		fromEnv, plain := commandFlags(t, c, named), commandFlags(t, c, empty)
		doc := ref[c]
		if plain == nil {
			for name := range doc {
				t.Errorf("%s: %s has no flags, but --%s is documented", cliReference, c, name)
			}
			continue
		}
		plain.VisitAll(func(f *flag.Flag) {
			row, ok := doc[f.Name]
			if !ok {
				t.Errorf("%s: %s --%s is not documented", cliReference, c, f.Name)
				return
			}
			isBool := false
			if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok {
				isBool = b.IsBoolFlag()
			}
			_, isDuration := f.Value.(flag.Getter).Get().(time.Duration)
			switch {
			case isBool && row.value != "":
				t.Errorf("%s: %s --%s is a boolean flag; document it without a value", cliReference, c, f.Name)
			case !isBool && row.value == "":
				t.Errorf("%s: %s --%s takes a value; document it as --%s VALUE", cliReference, c, f.Name, f.Name)
			case isDuration != (row.value == "DURATION"):
				t.Errorf("%s: %s --%s: document a duration as DURATION, and only a duration", cliReference, c, f.Name)
			}

			wantEnv := "none"
			if v := fromEnv.Lookup(f.Name).DefValue; strings.HasPrefix(v, "$"+brand.EnvPrefix) {
				wantEnv = "`" + strings.TrimPrefix(v, "$") + "`"
			}
			if row.env != wantEnv {
				t.Errorf("%s: %s --%s: env is %s, documented %s", cliReference, c, f.Name, wantEnv, row.env)
			}

			// A default in one code span is checked literally
			// "none" permits an empty value or false; other defaults are prose
			switch {
			case row.def == "none":
				if f.DefValue != "" && f.DefValue != "false" {
					t.Errorf("%s: %s --%s defaults to %q, documented as none", cliReference, c, f.Name, f.DefValue)
				}
			case regexp.MustCompile("^`[^`]*`$").MatchString(row.def):
				if want := strings.Trim(row.def, "`"); f.DefValue != want {
					t.Errorf("%s: %s --%s defaults to %q, documented %q", cliReference, c, f.Name, f.DefValue, want)
				}
			case row.def == "":
				t.Errorf("%s: %s --%s: the default is empty; write none for none", cliReference, c, f.Name)
			}
		})
		for name := range doc {
			if plain.Lookup(name) == nil {
				t.Errorf("%s: %s --%s is documented but doesn't exist", cliReference, c, name)
			}
		}
	}

	// Every variable the binary reads through envName
	used := map[string]bool{}
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range regexp.MustCompile(`envName\("([a-z-]+)"\)`).FindAllStringSubmatch(string(src), -1) {
			used[envName(m[1])] = true
		}
	}
	var want []string
	for k := range used {
		want = append(want, k)
	}
	sort.Strings(want)
	sort.Strings(refEnv)
	if strings.Join(want, " ") != strings.Join(refEnv, " ") {
		t.Errorf("%s: the Environment table lists %v; the binary reads %v", cliReference, refEnv, want)
	}
}

// TestCLIExitStatus checks the exit statuses docs/cli.md promises for usage errors and -h
func TestCLIExitStatus(t *testing.T) {
	code := func(args ...string) (int, string) {
		var out, errb bytes.Buffer
		c := run(args, strings.NewReader(""), &out, &errb, func(string) string { return "" })
		return c, out.String()
	}
	for _, tc := range []struct {
		args []string
		want int
	}{
		{nil, 2},
		{[]string{"no-such-command"}, 2},
		{[]string{"help"}, 0},
		{[]string{"-h"}, 0},
		{[]string{"--help"}, 0},
		{[]string{"version"}, 0},
		{[]string{"--version"}, 0},
		{[]string{"--version", "extra"}, 2},
		{[]string{"--version", "-x"}, 2},
	} {
		if got, _ := code(tc.args...); got != tc.want {
			t.Errorf("%v: exit %d, want %d", tc.args, got, tc.want)
		}
	}
	for _, c := range usageCommands() {
		help, bad := 0, 2
		switch c {
		case "hook":
			help = 2 // every error is a deny
		case "brief":
			bad = 0 // a briefing never stops a session
		}
		if got, out := code(c, "-h"); got != help || c == "hook" && !strings.Contains(out, `"deny"`) {
			t.Errorf("%s -h: exit %d, want %d (stdout %q)", c, got, help, out)
		}
		if got, out := code(c, "-no-such-flag"); got != bad || c == "hook" && !strings.Contains(out, `"deny"`) {
			t.Errorf("%s -no-such-flag: exit %d, want %d (stdout %q)", c, got, bad, out)
		}
	}
}

func TestCLIHelpFlagSpelling(t *testing.T) {
	singleDash := regexp.MustCompile(`(?m)^  -[a-z][a-z-]`)
	for _, command := range []string{"apply", "enroll", "explain", "keygen", "pull", "ship", "sign", "unlock", "verify"} {
		t.Run(command, func(t *testing.T) {
			var previous string
			for _, help := range []string{"-h", "--help"} {
				code, out, errs := call(t, "", command, help)
				if code != 0 || out != "" || !strings.Contains(errs, "  --") || singleDash.MatchString(errs) {
					t.Fatalf("%s %s: exit %d, stdout %q, stderr %q", command, help, code, out, errs)
				}
				if previous != "" && errs != previous {
					t.Fatalf("%s help differs between flag spellings", command)
				}
				if command == "explain" && !regexp.MustCompile(`(?m)^  -v\s`).MatchString(errs) {
					t.Fatalf("explain help does not show the -v alias: %q", errs)
				}
				previous = errs
			}
		})
	}
}

// noArgumentCommands returns the commands docs/cli.md documents as taking no arguments
func noArgumentCommands(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(cliReference)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	heading := regexp.MustCompile("(?m)^## `" + brand.Name + " ([a-z]+)`$")
	sections := heading.FindAllStringSubmatchIndex(string(data), -1)
	for i, m := range sections {
		end := len(data)
		if i+1 < len(sections) {
			end = sections[i+1][0]
		}
		if regexp.MustCompile(`(?m)\bNo (flags or )?arguments\.`).Match(data[m[1]:end]) {
			out = append(out, string(data[m[2]:m[3]]))
		}
	}
	return out
}

// TestCLIStrayArgument holds every command that docs/cli.md documents as
// taking no arguments to a usage error when one is given anyway. Go's flag
// parsing stops at the first word that isn't a flag, so a command that
// ignored the word would also ignore every flag after it
func TestCLIStrayArgument(t *testing.T) {
	dir := t.TempDir()
	// Each command line is valid on its own, so the stray argument is the only usage error
	valid := map[string][]string{
		"hook":    {"-policy", baseline},
		"brief":   {"-policy", baseline},
		"unlock":  {},
		"apply":   {"-policy", baseline, "-scope", "user"},
		"explain": {"-policy", baseline, "-command", "git"},
		"keygen":  {"-private", filepath.Join(dir, "k"), "-public", filepath.Join(dir, "k.pub")},
		"enroll":  {"-server", "https://127.0.0.1:1"},
		"ship":    {"-audit", filepath.Join(dir, "audit.jsonl")},
		"pull":    {"-out", filepath.Join(dir, "policy.yaml"), "-pubkey", filepath.Join(dir, "none.pub")},
		"version": {},
	}
	commands := noArgumentCommands(t)
	if len(commands) < len(valid) {
		t.Errorf("%s documents only %v as taking no arguments", cliReference, commands)
	}
	for _, c := range commands {
		args, ok := valid[c]
		if !ok {
			t.Errorf("%s takes no arguments: add a valid command line for it here", c)
			continue
		}
		stray := append(append([]string{c}, args...), "stray")
		code, out, errs := call(t, lsSrc, stray...)
		switch c {
		case "hook":
			if code != 2 || !strings.Contains(out, `"deny"`) {
				t.Errorf("%v: exit %d, stdout %q, want a deny with exit 2", stray, code, out)
			}
		case "brief":
			// A briefing never stops a session, so it only says it is misconfigured
			if code != 0 || !strings.Contains(out, "misconfigured") {
				t.Errorf("%v: exit %d, stdout %q, want exit 0 and a misconfigured briefing", stray, code, out)
			}
		default:
			if code != 2 {
				t.Errorf("%v: exit %d, want 2 (stderr %q)", stray, code, errs)
			}
		}
		if code, out, errs := call(t, lsSrc, append([]string{c}, args...)...); code == 2 || strings.Contains(out, "misconfigured") {
			t.Errorf("%s %v is not a valid command line: exit %d, stdout %q, stderr %q", c, args, code, out, errs)
		}
	}
}

// TestExplainJSONReference checks explain --json against the fields docs/cli.md lists
func TestExplainJSONReference(t *testing.T) {
	code, out, errs := call(t, "", "explain", "--json", "--policy", baseline, "--cwd", "/work/repo", "--command", "cat .env")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(cliReference)
	if err != nil {
		t.Fatal(err)
	}
	_, table, _ := strings.Cut(string(data), "`--json` prints one object")
	table, _, _ = strings.Cut(table, "Fields may be added.")
	documented := map[string]bool{}
	for _, m := range regexp.MustCompile("(?m)^\\| `([a-z]+)` \\|").FindAllStringSubmatch(table, -1) {
		documented[m[1]] = true
	}
	if len(documented) == 0 {
		t.Fatalf("%s documents no explain -json fields", cliReference)
	}
	for k := range v {
		if !documented[k] {
			t.Errorf("explain -json has field %q, which %s doesn't list", k, cliReference)
		}
	}
	if v["decision"] != "deny" || v["rule"] == "" || v["reason"] == "" {
		t.Errorf("explain -json: %s", out)
	}
}
