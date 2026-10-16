package claudecode

import (
	"context"
	"encoding/json"
	"io/fs"
	"os/exec"
	"slices"
	"testing"

	"cyberboar.dev/cyberboar/internal/adapters/claudecode/gitbash"
	"cyberboar.dev/cyberboar/internal/engine"
)

// On native Windows the home is USERPROFILE, HOME must agree with it, and
// directories may come in Git Bash's form
func TestWindowsEnv(t *testing.T) {
	files := map[string]string{`C:\Git\usr\bin\bash.exe`: "", `C:\Git\etc\fstab`: "none / cygdrive binary 0 0\n"}
	gitBash := func(getenv func(string) string) gitbash.Env {
		return gitbash.Env{Getenv: getenv,
			LookPath: func(string) (string, error) { return `C:\Git\cmd\git.exe`, nil },
			ReadFile: func(p string) ([]byte, error) { return []byte(files[p]), nil },
			Exists:   func(p string) bool { _, ok := files[p]; return ok }}
	}
	input := []byte(`{"hook_event_name":"PreToolUse","tool_name":"Read","cwd":"/c/work/repo","tool_input":{"file_path":"x"}}`)
	for _, tc := range []struct {
		name          string
		env           map[string]string
		home, project string
		refused       bool
	}{
		{"USERPROFILE only", map[string]string{"USERPROFILE": `C:\Users\dev`, "CLAUDE_PROJECT_DIR": `C:\work\repo`}, `C:\Users\dev`, `C:\work\repo`, false},
		{"HOME only, Git Bash form", map[string]string{"HOME": "/c/Users/dev", "CLAUDE_PROJECT_DIR": "/c/work/repo"}, `C:\Users\dev`, `C:\work\repo`, false},
		{"both agree in other case", map[string]string{"HOME": "/c/users/DEV", "USERPROFILE": `C:\Users\dev`}, `C:\Users\dev`, "", false},
		{"both disagree", map[string]string{"HOME": `D:\home`, "USERPROFILE": `C:\Users\dev`}, "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(k string) string { return tc.env[k] }
			c, err := parse(input, getenv, "windows", gitBash(getenv))
			if err != nil {
				t.Fatal(err)
			}
			if tc.refused {
				if c.Err == nil {
					t.Fatalf("differing HOME and USERPROFILE accepted: %+v", c.Actions)
				}
				return
			}
			if c.Err != nil || len(c.Actions) != 1 {
				t.Fatalf("actions %+v, err %v", c.Actions, c.Err)
			}
			a := c.Actions[0]
			if a.Platform != engine.PlatformWindows || a.Home != tc.home || a.Cwd != `C:\work\repo` {
				t.Errorf("action %+v", a)
			}
			if a.Mounts["/"] != `C:\Git` {
				t.Errorf("mounts %v", a.Mounts)
			}
			if tc.project != "" && (len(a.Workspaces) != 1 || a.Workspaces[0] != tc.project) {
				t.Errorf("workspaces %q, want %q", a.Workspaces, tc.project)
			}
		})
	}
}

// When Git Bash's mount table can't be read (here Git isn't installed), the
// adapter still answers, and the engine refuses the paths that only the
// table could place, such as /tmp
func TestWindowsWithoutMounts(t *testing.T) {
	noGit := gitbash.Env{Getenv: func(string) string { return "" },
		LookPath: func(string) (string, error) { return "", exec.ErrNotFound },
		ReadFile: func(string) ([]byte, error) { return nil, fs.ErrNotExist },
		Exists:   func(string) bool { return false }}
	if _, err := gitbash.Mounts(noGit); err == nil {
		t.Fatal("Mounts without Git succeeded")
	}
	c, err := engine.Compile(loadPolicy(t, "baseline.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	getenv := func(k string) string {
		return map[string]string{"USERPROFILE": `C:\Users\dev`, "CLAUDE_PROJECT_DIR": `C:\work\repo`}[k]
	}
	input := []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"C:\\work\\repo","tool_input":{"command":"cat /tmp/notes.txt"}}`)
	call, err := parse(input, getenv, "windows", noGit)
	if err != nil || call.Err != nil || len(call.Actions) == 0 {
		t.Fatalf("call %+v, err %v", call, err)
	}
	var vs []engine.Verdict
	for _, a := range call.Actions {
		if a.Mounts != nil {
			t.Errorf("action with mounts %v although they couldn't be read", a.Mounts)
		}
		vs = append(vs, engine.Evaluate(context.Background(), c, a))
	}
	if v, _ := engine.Strictest(vs); v.Decision != engine.Deny || v.Rule != engine.RuleWindowsPath {
		t.Errorf("verdict %s by %s (%s); want deny by %s", v.Decision, v.Rule, v.Reason, engine.RuleWindowsPath)
	}

	// With the table, the same command is checked against the policy
	files := map[string]string{`C:\Git\usr\bin\bash.exe`: "", `C:\Git\etc\fstab`: "none / cygdrive binary 0 0\n"}
	git := gitbash.Env{Getenv: getenv,
		LookPath: func(string) (string, error) { return `C:\Git\cmd\git.exe`, nil },
		ReadFile: func(p string) ([]byte, error) { return []byte(files[p]), nil },
		Exists:   func(p string) bool { _, ok := files[p]; return ok }}
	call, err = parse(input, getenv, "windows", git)
	if err != nil || call.Err != nil || len(call.Actions) == 0 {
		t.Fatalf("call %+v, err %v", call, err)
	}
	for _, a := range call.Actions {
		if v := engine.Evaluate(context.Background(), c, a); v.Rule == engine.RuleWindowsPath {
			t.Errorf("with the mount table: %s by %s (%s)", v.Decision, v.Rule, v.Reason)
		}
	}
}

func TestSettingsFiles(t *testing.T) {
	win := SettingsFiles(Env{Windows: true, Home: `C:\Users\dev`, ProjectDir: `C:\work\repo\`}, `D:\claude`, "windows")
	want := []string{
		`C:\Users\dev\.claude\settings.json`, `C:\Users\dev\.claude\settings.local.json`,
		`D:\claude\settings.json`, `D:\claude\settings.local.json`,
		`C:\work\repo\.claude\settings.json`, `C:\work\repo\.claude\settings.local.json`,
		`C:\Program Files\ClaudeCode`, `C:\ProgramData\ClaudeCode`,
	}
	if !slices.Equal(win, want) {
		t.Errorf("Windows: %q\nwant %q", win, want)
	}
	posix := SettingsFiles(Env{Home: "/home/dev", ProjectDir: "/work/repo"}, "", "darwin")
	if !slices.Contains(posix, "/work/repo/.claude/settings.local.json") || !slices.Contains(posix, "/home/dev/.claude/settings.json") ||
		slices.Contains(posix, "/settings.json") || !slices.Contains(posix, "/Library/Application Support/ClaudeCode") {
		t.Errorf("POSIX: %q", posix)
	}
}

// Claude Code's Glob searches the base directory of an absolute pattern
// and ignores its path field. A relative pattern is matched under path
func TestGlobBase(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		windows bool
		dir     string
	}{
		{"/home/dev/.ssh/*", false, "/home/dev/.ssh"},
		{"/home/dev/.ssh/**/id_*", false, "/home/dev/.ssh"},
		{"/home/dev/{.ssh,.aws}/*", false, "/home/dev"},
		{"/home/dev/.s[s]h/x", false, "/home/dev"},
		{"/home/dev/.ssh/id_rsa", false, "/home/dev/.ssh"},
		{"/home/dev/.ssh/", false, "/home/dev"},
		{"/etc*", false, "/"},
		{"/", false, "/"},
		{`/home/dev\*`, false, "/home"},
		{"src/**/*.go", false, ""},
		{"../../etc/*", false, ""},
		{`C:\x\*`, false, ""},
		{`C:\Users\dev\.ssh\*`, true, `C:\Users\dev\.ssh`},
		{`C:/Users/dev/.ssh/*`, true, `C:/Users/dev/.ssh`},
		{`C:\Users\dev/.ssh\*`, true, `C:\Users\dev/.ssh`},
		{`C:\*`, true, `C:\`},
		{`C:\`, true, `C:\`},
		{`C:\Users`, true, `C:\`},
		{`\Users\dev\*`, true, `\Users\dev`},
		{`\\server\share\*`, true, `\\server\share`},
		{"/c/Users/dev/.ssh/*", true, "/c/Users/dev/.ssh"},
		{`C:x\*`, true, ""},
		{`1:\x\*`, true, ""},
		{`src\*`, true, ""},
	} {
		dir, ok := globBase(tc.pattern, tc.windows)
		if dir != tc.dir || ok != (tc.dir != "") {
			t.Errorf("globBase(%q, windows %v) = %q, %v; want %q", tc.pattern, tc.windows, dir, ok, tc.dir)
		}
	}
}

// MCP calls say their names are in Claude Code's form, whichever way the split is found
func TestMCPCallsHaveClaudeCodeNames(t *testing.T) {
	for _, server := range []string{"", "fs.srv"} {
		in := &Input{HookEventName: "PreToolUse", Cwd: "/work", ToolName: "mcp__fs_srv__write_file", ToolInput: json.RawMessage(`{}`)}
		if server != "" {
			in.MCPServer = &struct {
				Name   string `json:"name"`
				Source string `json:"source"`
			}{Name: server}
		}
		actions, err := Actions(in, Env{ProjectDir: "/work", Home: "/home/dev"})
		if err != nil || len(actions) == 0 {
			t.Fatalf("server %q: %d actions, %v", server, len(actions), err)
		}
		for _, a := range actions {
			if a.MCP.Names != engine.NamesClaudeCode {
				t.Errorf("server %q: %+v", server, a.MCP)
			}
		}
	}
}
