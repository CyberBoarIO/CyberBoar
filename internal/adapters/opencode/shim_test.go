package opencode_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/adapters/opencode"
)

// fakeHook stands in for the hook command: it records its input, arguments
// and directory, then answers as FAKE_MODE (or FAKE_BRIEF for the briefing) says.
const fakeHook = `#!/bin/sh
if [ "$1" = brief ]; then
  case "$FAKE_BRIEF" in
    ok) printf '{"additionalContext":"BRIEF TEXT"}\n' ;;
    empty) ;;
    fail) exit 1 ;;
  esac
  exit 0
fi
cat > "$FAKE_DIR/input.json"
pwd > "$FAKE_DIR/cwd"
case "$FAKE_MODE" in
  none) printf '{"decision":"none"}\n' ;;
  none-spaced) printf ' { "decision" : "none" } \n\n' ;;
  empty) ;;
  extra) printf '{"decision":"none","also":1}\n' ;;
  allow) printf '{"decision":"allow"}\n' ;;
  trailing) printf '{"decision":"none"} {}\n' ;;
  array) printf '[{"decision":"none"}]\n' ;;
  deny) printf '{"decision":"deny","reason":"cyberboar: no way"}\n'; echo "cyberboar: no way" >&2; exit 2 ;;
  hook-setup) printf '{"hookSpecificOutput":{"permissionDecisionReason":"misconfigured"}}\n'; exit 2 ;;
  none-exit1) printf '{"decision":"none"}\n'; exit 1 ;;
  stderr) echo "boom" >&2; exit 3 ;;
  silent) exit 1 ;;
  sleep) exec sleep 5 ;;
  flood) head -c 2000000 /dev/zero | tr '\0' a ;;
  signal) kill -9 $$ ;;
esac
`

// driver loads the plugin like opencode does, runs the config hook (unless
// told not to), one tool.execute.before and the system prompt transform, and
// prints what happened.
const driver = `import { pathToFileURL } from "node:url";
const [shim, skipConfig] = process.argv.slice(2);
const mod = await import(pathToFileURL(shim).href);
const hooks = await mod.plugin({ directory: "/w/repo/sub", worktree: "/w/repo" });
if (skipConfig !== "noconfig") await hooks.config({ shell: "/bin/zsh", mcp: { zeta: {}, alpha: {} } });
const out = {};
try {
  await hooks["tool.execute.before"]({ tool: "bash", sessionID: "s1", callID: "c1" }, { args: { command: "ls" } });
  out.ok = true;
} catch (e) {
  out.ok = false;
  out.message = String(e?.message ?? e);
}
const transform = hooks["experimental.chat.system.transform"];
if (transform) {
  const o = { system: ["base"] };
  await transform({ sessionID: "s1" }, o);
  out.system = o.system;
}
console.log(JSON.stringify(out));
`

type shimResult struct {
	OK      bool     `json:"ok"`
	Message string   `json:"message"`
	System  []string `json:"system"`
}

// runtimes are the JavaScript runtimes on this machine that can load the
// plugin: opencode itself runs on Bun; Node behaves the same for the APIs the
// shim uses.
func runtimes(t *testing.T) []string {
	if runtime.GOOS == "windows" {
		t.Skip("the fake hook is a POSIX shell script")
	}
	var out []string
	for _, name := range []string{"bun", "node"} {
		if p, err := exec.LookPath(name); err == nil {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		t.Skip("neither bun nor node is installed")
	}
	return out
}

// shimDir writes the fake hook and a plugin that runs it; for the project
// scope the plugin sits in proj/.opencode/plugin.
func shimDir(t *testing.T, o opencode.ShimOptions, timeoutMs string) (dir, shim string) {
	dir = t.TempDir()
	hookPath := filepath.Join(dir, "fake hook")
	if err := os.WriteFile(hookPath, []byte(fakeHook), 0o755); err != nil {
		t.Fatal(err)
	}
	if o.Command == "" {
		o.Command = hookPath
	}
	out, err := opencode.Shim(o)
	if err != nil {
		t.Fatal(err)
	}
	if timeoutMs != "" {
		out = []byte(strings.Replace(string(out), "const timeoutMs = 15000;", "const timeoutMs = "+timeoutMs+";", 1))
	}
	pluginDir := filepath.Join(dir, "proj", ".opencode", "plugin")
	os.MkdirAll(pluginDir, 0o755)
	shim = filepath.Join(pluginDir, opencode.FileName)
	for name, data := range map[string]string{shim: string(out), filepath.Join(dir, "package.json"): `{"type":"module"}`,
		filepath.Join(dir, "driver.js"): driver} {
		if err := os.WriteFile(name, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir, shim
}

func runShim(t *testing.T, js, dir, shim string, env []string, args ...string) shimResult {
	t.Helper()
	cmd := exec.Command(js, append([]string{filepath.Join(dir, "driver.js"), shim}, args...)...)
	cmd.Env = append(os.Environ(), append([]string{"FAKE_DIR=" + dir}, env...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s driver: %v\n%s", filepath.Base(js), err, out)
	}
	var r shimResult
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &r); err != nil {
		t.Fatalf("driver output %q: %v", out, err)
	}
	return r
}

// The shim lets a call through only on exit 0 with exactly
// {"decision":"none"}; every other answer, and every failure to get one,
// blocks it.
func TestShimFailsClosed(t *testing.T) {
	for _, js := range runtimes(t) {
		dir, shim := shimDir(t, opencode.ShimOptions{Scope: opencode.ScopeUser, Policy: "/p.yaml", Deadline: "5s"}, "1000")
		for _, tc := range []struct {
			mode, message string
			ok            bool
		}{
			{"none", "", true},
			{"none-spaced", "", true},
			{"empty", "exit status 0 and no reason", false},
			{"extra", "no reason", false},
			{"allow", "no reason", false},
			{"trailing", "exit status 0", false},
			{"array", "exit status 0", false},
			{"deny", "cyberboar: no way", false},
			{"hook-setup", "misconfigured", false},
			{"none-exit1", "exit status 1", false},
			{"stderr", "boom", false},
			{"silent", "exit status 1 and no reason", false},
			{"sleep", "no answer within 1000 ms", false},
			{"flood", "more output than a hook answer", false},
			{"signal", "signal SIGKILL", false},
		} {
			r := runShim(t, js, dir, shim, []string{"FAKE_MODE=" + tc.mode})
			if r.OK != tc.ok || !strings.Contains(r.Message, tc.message) {
				t.Errorf("%s, %s: ok %v message %q; want ok %v, message containing %q", filepath.Base(js), tc.mode, r.OK, r.Message, tc.ok, tc.message)
			}
		}

		// A hook that can't be started
		dir, shim = shimDir(t, opencode.ShimOptions{Scope: opencode.ScopeUser, Command: filepath.Join(t.TempDir(), "missing"), Policy: "/p.yaml", Deadline: "5s"}, "")
		if r := runShim(t, js, dir, shim, nil); r.OK || !strings.Contains(r.Message, "could not run") {
			t.Errorf("%s, missing hook: %+v", filepath.Base(js), r)
		}
	}
}

// The shim sends the call, the session directory, the worktree and what the
// config hook reported; before the config hook runs it sends null for the
// latter, which the hook refuses.
func TestShimInput(t *testing.T) {
	for _, js := range runtimes(t) {
		dir, shim := shimDir(t, opencode.ShimOptions{Scope: opencode.ScopeUser, Policy: "/p.yaml", Deadline: "5s"}, "")
		for _, skip := range []string{"", "noconfig"} {
			if r := runShim(t, js, dir, shim, []string{"FAKE_MODE=none"}, skip); !r.OK {
				t.Fatalf("%s: %+v", filepath.Base(js), r)
			}
			data, err := os.ReadFile(filepath.Join(dir, "input.json"))
			if err != nil {
				t.Fatal(err)
			}
			want := `{"tool":"bash","sessionID":"s1","callID":"c1","args":{"command":"ls"},"directory":"/w/repo/sub","worktree":"/w/repo","shell":"/bin/zsh","mcpServers":["alpha","zeta"]}`
			if skip != "" {
				want = `{"tool":"bash","sessionID":"s1","callID":"c1","args":{"command":"ls"},"directory":"/w/repo/sub","worktree":"/w/repo","shell":null,"mcpServers":null}`
			}
			if string(data) != want {
				t.Errorf("%s %s: input\n%s\nwant\n%s", filepath.Base(js), skip, data, want)
			}
			in, err := opencode.ParseInput(data)
			if (err == nil) != (skip == "") {
				t.Errorf("%s %s: ParseInput: %+v, %v", filepath.Base(js), skip, in, err)
			}
		}
	}
}

// A project-scope plugin runs the hook in the project root, which its
// relative policy path is relative to; a user-scope one where opencode runs.
func TestShimDirectory(t *testing.T) {
	for _, js := range runtimes(t) {
		for _, scope := range []opencode.Scope{opencode.ScopeProject, opencode.ScopeUser} {
			dir, shim := shimDir(t, opencode.ShimOptions{Scope: scope, Policy: "p.yaml", Deadline: "5s"}, "")
			if r := runShim(t, js, dir, shim, []string{"FAKE_MODE=none"}); !r.OK {
				t.Fatalf("%s: %+v", filepath.Base(js), r)
			}
			got, _ := os.ReadFile(filepath.Join(dir, "cwd"))
			want, _ := filepath.EvalSymlinks(filepath.Join(dir, "proj"))
			if scope == opencode.ScopeUser {
				want, _ = os.Getwd()
			}
			if strings.TrimSpace(string(got)) != want {
				t.Errorf("%s %s: hook ran in %q, want %q", filepath.Base(js), scope, strings.TrimSpace(string(got)), want)
			}
		}
	}
}

// The briefing goes into the system prompt; when it can't be loaded the
// model is told that calls are still checked.
func TestShimBriefing(t *testing.T) {
	for _, js := range runtimes(t) {
		dir, shim := shimDir(t, opencode.ShimOptions{Scope: opencode.ScopeUser, Policy: "/p.yaml", Deadline: "5s", Briefing: true}, "")
		for mode, want := range map[string][]string{
			"ok":    {"base", "BRIEF TEXT"},
			"empty": {"base"},
			"fail":  {"base", "cyberboar: the policy briefing could not be loaded. Every tool call is still checked against the policy."},
		} {
			r := runShim(t, js, dir, shim, []string{"FAKE_MODE=none", "FAKE_BRIEF=" + mode})
			if strings.Join(r.System, "|") != strings.Join(want, "|") {
				t.Errorf("%s %s: system %q, want %q", filepath.Base(js), mode, r.System, want)
			}
		}
		dir, shim = shimDir(t, opencode.ShimOptions{Scope: opencode.ScopeUser, Policy: "/p.yaml", Deadline: "5s"}, "")
		if r := runShim(t, js, dir, shim, []string{"FAKE_MODE=none", "FAKE_BRIEF=ok"}); r.System != nil {
			t.Errorf("%s: briefing off, system %q", filepath.Base(js), r.System)
		}
	}
}
