package adapters_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/adapters"
)

func TestCheckFields(t *testing.T) {
	fields := []string{"file_path", "paths", "paths[]", "files.*", "files.*.from"}
	for _, c := range []struct {
		input string
		ok    bool
	}{
		{`{}`, true},
		{`{"file_path": null}`, true},
		{`{"file_path": "a"}`, true},
		{`{"paths": "a"}`, true},
		{`{"paths": ["a", "b"]}`, true},
		{`{"paths": []}`, true},
		{`{"files": {"x": "a", "y": {"from": "b"}}}`, true},
		{`{"unrelated": [1]}`, true},
		{`{"file_path": ["a"]}`, false},
		{`{"file_path": 1}`, false},
		{`{"file_path": {"a": "b"}}`, false},
		{`{"paths": [1]}`, false},
		{`{"paths": [["a"]]}`, false},
		{`{"files": {"x": 1}}`, false},
		{`{"files": {"x": {"from": ["a"]}}}`, false},
		{`{"files": "a"}`, false},
	} {
		var v any
		if err := json.Unmarshal([]byte(c.input), &v); err != nil {
			t.Fatal(err)
		}
		if err := adapters.CheckFields(v, fields); (err == nil) != c.ok {
			t.Errorf("CheckFields(%s) = %v, want ok %v", c.input, err, c.ok)
		}
	}
}

func TestToolInputObject(t *testing.T) {
	for _, tc := range []struct {
		name, data       string
		required, fields []string
		want             string
	}{
		{"invalid JSON", "{", nil, nil, "the sample tool input is not a JSON object"},
		{"null", "null", nil, nil, "the sample tool input is not a JSON object"},
		{"array", "[]", nil, nil, "the sample tool input is not a JSON object"},
		{"missing required", `{}`, []string{"path"}, nil, `the sample tool input has no "path"`},
		{"null required", `{"path":null}`, []string{"path"}, nil, `the sample tool input has no "path"`},
		{"required before shape", `{"path":1}`, []string{"other"}, []string{"path"}, `the sample tool input has no "other"`},
		{"bad path shape", `{"path":1}`, []string{"path"}, []string{"path"}, `the sample tool input is malformed: field "path" holds a number, which is not read as a path`},
		{"optional null", `{"path":null}`, nil, []string{"path"}, ""},
		{"optional absent", `{}`, nil, []string{"path"}, ""},
		{"path variants", `{"paths":["a"],"files":{"x":{"from":"b"}}}`, []string{"paths"}, []string{"paths[]", "files.*.from"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := adapters.ToolInputObject("sample", json.RawMessage(tc.data), tc.required, tc.fields)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var invalid *adapters.Error
			if !errors.As(err, &invalid) || invalid.Rule != adapters.RuleInvalidInput || invalid.Msg != tc.want {
				t.Fatalf("got %v, want invalid input: %s", err, tc.want)
			}
		})
	}
	input, err := adapters.ToolInputObject("sample", json.RawMessage(`{"line":9007199254740993}`), []string{"line"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n, ok := input["line"].(json.Number); !ok || n.String() != "9007199254740993" {
		t.Fatalf("JSON number lost precision or type: %#v", input["line"])
	}
}

func TestShellCommand(t *testing.T) {
	for sh, want := range map[string]string{
		"/bin/bash": "ls", "zsh": "ls", "/bin/sh": "ls", "DASH.EXE": "ls",
		"pwsh": "pwsh -Command 'ls'", "powershell.exe": "pwsh -Command 'ls'",
		"cmd.exe": "fish -c 'ls'", "/usr/bin/fish": "fish -c 'ls'", "": "fish -c 'ls'",
	} {
		if got := adapters.ShellCommand(sh, "ls"); got != want {
			t.Errorf("ShellCommand(%q, ls) = %q, want %q", sh, got, want)
		}
	}
}

func TestIsDir(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{dir: true, file: false, filepath.Join(dir, "missing"): false, "": false}
	if link := filepath.Join(dir, "link"); os.Symlink(dir, link) == nil {
		want[link] = true
	}
	for path, isDir := range want {
		if got := adapters.IsDir(path); got != isDir {
			t.Errorf("IsDir(%q) = %v, want %v", path, got, isDir)
		}
	}
}

// The startup files are bash's and sh's in the home directory, zsh's there
// and in an absolute ZDOTDIR, and absolute BASH_ENV and ENV; a relative one
// can't be guarded and is left out. On Windows Git Bash's form is read.
func TestStartupFiles(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	got := adapters.StartupFiles(false, "/home/dev", env(map[string]string{"ZDOTDIR": "/home/dev/.config/zsh", "BASH_ENV": "rel.sh", "ENV": "/etc/shrc.local"}))
	for _, want := range []string{"/home/dev/.bashrc", "/home/dev/.profile", "/home/dev/.bash_logout", "/home/dev/.zshenv",
		"/home/dev/.config/zsh/.zshrc", "/home/dev/.config/zsh/.zlogout", "/etc/shrc.local"} {
		if !slices.Contains(got, want) {
			t.Errorf("no %s in %q", want, got)
		}
	}
	if slices.Contains(got, "rel.sh") {
		t.Errorf("relative BASH_ENV guarded: %q", got)
	}
	win := adapters.StartupFiles(true, `C:\Users\dev`, env(map[string]string{"BASH_ENV": "/c/Users/dev/env.sh", "ZDOTDIR": "zsh"}))
	if !slices.Contains(win, `C:\Users\dev\.bashrc`) || !slices.Contains(win, `C:\Users\dev\env.sh`) || slices.ContainsFunc(win, func(p string) bool { return strings.HasPrefix(p, "zsh") }) {
		t.Errorf("Windows: %q", win)
	}
	if got := adapters.StartupFiles(false, "", env(nil)); got != nil {
		t.Errorf("no home: %q", got)
	}
}
