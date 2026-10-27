package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/pkg/sign"
)

func TestApplyUserScope(t *testing.T) {
	home := t.TempDir()
	env := func(k string) string { return map[string]string{"HOME": home}[k] }
	settings := filepath.Join(home, ".claude", "settings.json")
	apply := func(extra ...string) (int, string) {
		var out, errb bytes.Buffer
		args := append([]string{"apply", "--policy", baseline, "--scope", "user", "--command", "/opt/cyberboar"}, extra...)
		code := run(args, nil, &out, &errb, env)
		return code, out.String() + errb.String()
	}

	if code, out := apply(); code != 0 || !strings.Contains(out, "dry run") {
		t.Fatalf("dry run: exit %d\n%s", code, out)
	}
	if _, err := os.Stat(settings); !os.IsNotExist(err) {
		t.Fatal("a dry run wrote the settings")
	}

	os.MkdirAll(filepath.Dir(settings), 0o755)
	os.WriteFile(settings, []byte(`{"model": "opus"}`), 0o600)
	if code, out := apply("--write"); code != 0 || !strings.Contains(out, "wrote "+settings) {
		t.Fatalf("write: exit %d\n%s", code, out)
	}
	got, _ := os.ReadFile(settings)
	if !strings.Contains(string(got), `"model": "opus"`) || !strings.Contains(string(got), `"/opt/cyberboar"`) {
		t.Errorf("settings after apply:\n%s", got)
	}
	if bak, _ := os.ReadFile(settings + ".bak"); string(bak) != `{"model": "opus"}` {
		t.Errorf("backup = %q", bak)
	}
	if info, _ := os.Stat(settings); info.Mode().Perm() != 0o600 {
		t.Errorf("mode changed to %v", info.Mode().Perm())
	}
	if code, _ := apply("--write"); code != 0 {
		t.Fatal("second apply failed")
	}
	if again, _ := os.ReadFile(settings); !bytes.Equal(again, got) {
		t.Error("re-applying the same policy changed the settings")
	}
	if _, out := apply(); !strings.Contains(out, "disableAllHooks") || !strings.Contains(out, "--scope managed --lock") {
		t.Errorf("apply must say that users can switch hooks off:\n%s", out)
	}

	off := []byte(`{"disableAllHooks": true}`)
	os.WriteFile(settings, off, 0o600)
	if code, out := apply("--write"); code != 1 || !strings.Contains(out, "disableAllHooks") {
		t.Errorf("settings with hooks switched off: exit %d\n%s", code, out)
	}
	if after, _ := os.ReadFile(settings); !bytes.Equal(after, off) {
		t.Errorf("a refused apply changed the settings:\n%s", after)
	}
}

func TestSettingsBackupDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	settings, target := filepath.Join(dir, "settings.json"), filepath.Join(dir, "unrelated.txt")
	const old = `{"model":"original"}`
	const untouched = "unrelated content\n"
	if err := os.WriteFile(settings, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(untouched), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, settings+".bak"); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := writeAtomic(settings, []byte(`{"model":"updated"}`)); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != untouched {
		t.Fatalf("backup changed the symlink target: %q, %v", got, err)
	}
	if got, err := os.ReadFile(settings + ".bak"); err != nil || string(got) != old {
		t.Fatalf("backup lost the original settings: %q, %v", got, err)
	}
}

func TestApplyProjectScope(t *testing.T) {
	proj := t.TempDir()
	os.MkdirAll(filepath.Join(proj, ".cyberboar"), 0o755)
	pol, _ := os.ReadFile(baseline)
	os.WriteFile(filepath.Join(proj, ".cyberboar", "policy.yaml"), pol, 0o644)
	var out, errb bytes.Buffer
	code := run([]string{"apply", "--policy", filepath.Join(proj, ".cyberboar", "policy.yaml"), "--scope", "project", "--dir", proj, "--write"},
		nil, &out, &errb, testEnv)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	got, _ := os.ReadFile(filepath.Join(proj, ".claude", "settings.json"))
	if !strings.Contains(string(got), `"${CLAUDE_PROJECT_DIR}/.cyberboar/policy.yaml"`) || !strings.Contains(string(got), `"command": "cyberboar"`) {
		t.Errorf("committed settings must be portable:\n%s", got)
	}
}

// A flag value or combination apply doesn't take is a usage error (exit 2),
// whatever the policy. A command line that can't be carried out fails with exit 1
func TestApplyRefuses(t *testing.T) {
	proj := t.TempDir()
	missing := filepath.Join(proj, "none.yaml")
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"policy outside the project", []string{"--policy", baseline, "--scope", "project", "--dir", proj}, 1},
		{"missing policy", []string{"--policy", missing}, 1},
		{"deadline not below the hook timeout", []string{"--policy", missing, "--scope", "user", "--deadline", "9500ms"}, 2},
		{"unknown scope", []string{"--policy", missing, "--scope", "global"}, 2},
		{"lock outside the managed scope", []string{"--policy", missing, "--scope", "user", "--lock"}, 2},
		{"lock for an agent that can't lock", []string{"--policy", missing, "--agent", "cursor", "--scope", "managed", "--lock", "--allow-unsigned"}, 2},
		{"unknown agent", []string{"--policy", missing, "--agent", "windsurf", "--write"}, 2},
		{"managed scope without a key", []string{"--policy", missing, "--scope", "managed", "--managed-dir", proj}, 2},
		{"stray argument", []string{"--policy", baseline, "--scope", "user", "extra", "--write"}, 2},
	} {
		var out, errb bytes.Buffer
		args := append([]string{"apply"}, tc.args...)
		if code := run(args, nil, &out, &errb, testEnv); code != tc.want {
			t.Errorf("%s: exit %d, want %d (%s)", tc.name, code, tc.want, errb.String())
		}
	}
	if entries, _ := os.ReadDir(proj); len(entries) != 0 {
		t.Error("a refused apply wrote files")
	}
}

// Agents whose user-scope settings live under HOME refuse to install without
// it, with the message naming HOME
func TestApplyNeedsHome(t *testing.T) {
	noEnv := func(string) string { return "" }
	for _, agent := range []string{"codex", "copilot-cli", "cursor", "opencode"} {
		var out, errb bytes.Buffer
		code := run([]string{"apply", "-agent", agent, "-policy", baseline, "-scope", "user"}, nil, &out, &errb, noEnv)
		if code != 1 || errb.String() != "apply: HOME is not set\n" {
			t.Errorf("%s: exit %d, stderr %q; want exit 1 and HOME is not set", agent, code, errb.String())
		}
	}
}

func testKey(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	pub := filepath.Join(dir, "k.pub")
	if err := sign.Keygen(filepath.Join(dir, "k"), pub); err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestApplyManagedDropIn(t *testing.T) {
	dir := t.TempDir()
	pub := testKey(t)
	var out, errb bytes.Buffer
	code := run([]string{"apply", "--policy", baseline, "--scope", "managed", "--managed-dir", dir, "--lock", "--write",
		"--command", "/usr/local/bin/cyberboar", "--pubkey", pub}, nil, &out, &errb, testEnv)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	got, err := os.ReadFile(filepath.Join(dir, "managed-settings.d", "50-cyberboar.json"))
	if err != nil || !strings.Contains(string(got), `"allowManagedHooksOnly": true`) || !strings.Contains(string(got), `"disableAllHooks": false`) ||
		!strings.Contains(string(got), pub) {
		t.Errorf("drop-in: %v\n%s", err, got)
	}
	if strings.Contains(out.String(), "disableAllHooks") {
		t.Errorf("a locked managed install can't be switched off, yet apply says it can:\n%s", out.String())
	}
	// Managed scope without a key needs an explicit opt-out.
	if code := run([]string{"apply", "--policy", baseline, "--scope", "managed", "--managed-dir", t.TempDir()}, nil, &out, &errb, testEnv); code != 2 {
		t.Errorf("managed scope without -pubkey: exit %d", code)
	}
	if code := run([]string{"apply", "--policy", baseline, "--scope", "managed", "--managed-dir", t.TempDir(), "--allow-unsigned"}, nil, &out, &errb, testEnv); code != 0 {
		t.Errorf("managed scope with -allow-unsigned: exit %d", code)
	}
}

// On Windows Codex runs hooks with cmd.exe, so the hook is a command line in
// double quotes, given as commandWindows too, in the user's .codex under
// USERPROFILE, and managed requirements name windows_managed_dir. A project
// hook, which finds the policy from the git root, can't be written for cmd,
// and nor can a value cmd would change
func TestApplyCodexWindows(t *testing.T) {
	env := func(k string) string {
		return map[string]string{"USERPROFILE": `C:\Users\dev`, "HOME": "/home/ignored", "ProgramData": `D:\ProgramData`}[k]
	}
	h := host{getenv: env, goos: "windows", now: time.Now}
	run1 := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := h.run(append([]string{"apply", "--agent", "codex", "--policy", baseline, "--command", `C:\cb\cyberboar.exe`}, args...), nil, &out, &errb)
		return code, out.String(), errb.String()
	}
	code, out, errs := run1("--scope", "user")
	line := `\"C:\\cb\\cyberboar.exe\" hook --agent codex --policy \"`
	if code != 0 || !strings.Contains(out, `C:\Users\dev\.codex\hooks.json`) || strings.Count(out, line) != 2 || strings.Contains(out, `'C:`) {
		t.Errorf("user scope: exit %d %s\n%s", code, errs, out)
	}
	if !strings.Contains(out, `"commandWindows": "`+line) {
		t.Errorf("no commandWindows:\n%s", out)
	}
	code, out, errs = run1("--scope", "managed", "--allow-unsigned")
	if code != 0 || !strings.Contains(out, `D:\ProgramData\OpenAI\Codex\requirements.toml`) ||
		!strings.Contains(out, `windows_managed_dir = "C:\\cb"`) || !strings.Contains(out, "command_windows = ") {
		t.Errorf("managed scope: exit %d %s\n%s", code, errs, out)
	}
	if code, _, errs := run1("--scope", "project"); code != 2 || !strings.Contains(errs, "--scope user") {
		t.Errorf("project scope: exit %d %s", code, errs)
	}
	if code, _, errs := run1("--scope", "user", "--audit", `C:\logs\%USERNAME%.jsonl`); code != 1 || !strings.Contains(errs, "cmd.exe") {
		t.Errorf("percent sign: exit %d %s", code, errs)
	}
}

func TestApplyCodex(t *testing.T) {
	home := t.TempDir()
	env := func(k string) string { return map[string]string{"HOME": home}[k] }
	run1 := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := run(append([]string{"apply", "-agent", "codex", "-policy", baseline}, args...), strings.NewReader(""), &out, &errb, env)
		return code, out.String(), errb.String()
	}
	if code, out, errs := run1("-scope", "user", "-write", "-command", "/usr/local/bin/cyberboar"); code != 0 || !strings.Contains(out, "trust them in /hooks") {
		t.Fatalf("user scope: exit %d %s %s", code, out, errs)
	}
	got, err := os.ReadFile(filepath.Join(home, ".codex", "hooks.json"))
	if err != nil || !strings.Contains(string(got), `hook --agent codex`) {
		t.Fatalf("hooks.json: %v %s", err, got)
	}
	// Codex reads the user's hooks from CODEX_HOME when it is set
	codexHome := t.TempDir()
	for _, tc := range []struct {
		dir  string
		code int
	}{{codexHome, 0}, {"rel/codex", 1}} {
		var out, errb bytes.Buffer
		envHome := func(k string) string { return map[string]string{"HOME": home, "CODEX_HOME": tc.dir}[k] }
		code := run([]string{"apply", "-agent", "codex", "-policy", baseline, "-scope", "user", "-write", "-command", "/usr/local/bin/cyberboar"}, strings.NewReader(""), &out, &errb, envHome)
		if code != tc.code {
			t.Errorf("CODEX_HOME %s: exit %d %s", tc.dir, code, errb.String())
		}
	}
	if got, err := os.ReadFile(filepath.Join(codexHome, "hooks.json")); err != nil || !strings.Contains(string(got), `hook --agent codex`) {
		t.Errorf("hooks.json in CODEX_HOME: %v %s", err, got)
	}

	managed := t.TempDir()
	if code, _, errs := run1("-scope", "managed", "-managed-dir", managed, "-write", "-lock", "-pubkey", testKey(t)); code != 0 {
		t.Fatalf("managed: %s", errs)
	}
	req, _ := os.ReadFile(filepath.Join(managed, "requirements.toml"))
	if !strings.Contains(string(req), "allow_managed_hooks_only = true") || !strings.Contains(string(req), `decision = "forbidden"`) {
		t.Errorf("requirements.toml:\n%s", req)
	}
	// A requirements.toml someone else wrote is never overwritten.
	os.WriteFile(filepath.Join(managed, "requirements.toml"), []byte("[features]\nweb_search = false\n"), 0o644)
	if code, _, errs := run1("-scope", "managed", "-managed-dir", managed, "-write", "-allow-unsigned"); code != 1 || !strings.Contains(errs, "merge") {
		t.Errorf("overwrote a foreign requirements.toml: exit %d %s", code, errs)
	}

	for _, args := range [][]string{
		{"-scope", "user", "-lock"},
		{"-scope", "local"},
		{"-scope", "user", "-deadline", "9500ms"},
		{"-scope", "project", "-dir", t.TempDir()}, // policy outside the project
	} {
		if code, _, _ := run1(args...); code == 0 {
			t.Errorf("%v: accepted", args)
		}
	}
	var errb bytes.Buffer
	if code := run([]string{"apply", "-agent", "windsurf", "-policy", baseline}, strings.NewReader(""), &bytes.Buffer{}, &errb, env); code != 2 {
		t.Errorf("unknown agent: exit %d", code)
	}
}

func TestApplyCopilot(t *testing.T) {
	home := t.TempDir()
	env := func(k string) string { return map[string]string{"HOME": home}[k] }
	run1 := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := run(append([]string{"apply", "-agent", "copilot-cli", "-policy", baseline}, args...), strings.NewReader(""), &out, &errb, env)
		return code, out.String(), errb.String()
	}
	if code, out, errs := run1("-scope", "user", "-write", "-command", "/usr/local/bin/cyberboar"); code != 0 || !strings.Contains(out, "times out") ||
		!strings.Contains(out, "Local agent run this hook too") {
		t.Fatalf("user scope: exit %d %s %s", code, out, errs)
	}
	got, err := os.ReadFile(filepath.Join(home, ".copilot", "hooks", "cyberboar.json"))
	if err != nil || !strings.Contains(string(got), `'copilot-cli'`) || !strings.Contains(string(got), `"preToolUse"`) {
		t.Fatalf("hooks file: %v %s", err, got)
	}
	// Copilot 1.0.97 writes config.json with comments
	config := filepath.Join(home, ".copilot", "config.json")
	firstLaunch := time.Unix(0, 0).UTC().Format(time.RFC3339Nano)
	os.WriteFile(config, []byte("// User settings belong in settings.json.\n// This file is managed automatically.\n{\n  \"firstLaunchAt\": \""+firstLaunch+"\"\n}\n"), 0o600)
	if code, _, errs := run1("-scope", "user", "-command", "/usr/local/bin/cyberboar"); code != 0 {
		t.Errorf("config.json with comments: exit %d %s", code, errs)
	}
	os.Remove(config)
	managed := t.TempDir()
	if code, out, errs := run1("-scope", "managed", "-managed-dir", managed, "-write", "-allow-unsigned"); code != 0 ||
		!strings.Contains(out, "Local agent doesn't read "+managed+", so it runs without this hook") {
		t.Fatalf("managed: exit %d %s %s", code, out, errs)
	}
	// VS Code's Local agent reads ~/.copilot/hooks
	for _, tc := range []struct {
		dir   string
		local bool
	}{{filepath.Join(home, "copilot-home"), false}, {filepath.Join(home, ".copilot") + "/", true}} {
		var out, errb bytes.Buffer
		cenv := func(k string) string { return map[string]string{"HOME": home, "COPILOT_HOME": tc.dir}[k] }
		code := run([]string{"apply", "-agent", "copilot-cli", "-policy", baseline, "-scope", "user", "-command", "/usr/local/bin/cyberboar"},
			strings.NewReader(""), &out, &errb, cenv)
		if code != 0 || strings.Contains(out.String(), "Local agent run this hook too") != tc.local {
			t.Errorf("COPILOT_HOME=%s: exit %d %s %s", tc.dir, code, out.String(), errb.String())
		}
	}
	if _, err := os.Stat(filepath.Join(managed, "cyberboar.json")); err != nil {
		t.Error(err)
	}
	// Copilot runs no user or repository hook while its settings have disableAllHooks set
	repo := filepath.Join(home, "repo")
	os.MkdirAll(filepath.Join(repo, ".github", "copilot"), 0o755)
	data, _ := os.ReadFile(baseline)
	os.WriteFile(filepath.Join(repo, "policy.yaml"), data, 0o600)
	for _, tc := range []struct{ file, scope, settings, want string }{
		{filepath.Join(home, ".copilot", "config.json"), "user", `{"disableAllHooks": true}`, "disableAllHooks"},
		{filepath.Join(home, ".copilot", "settings.json"), "user", `{"disableAllHooks": true}`, "disableAllHooks"},
		{filepath.Join(repo, ".github", "copilot", "settings.json"), "project", `{"disableAllHooks": true}`, "disableAllHooks"},
		{filepath.Join(repo, ".github", "copilot", "settings.local.json"), "project", `{"disableAllHooks": true}`, "disableAllHooks"},
		{filepath.Join(home, ".copilot", "config.json"), "user", `{"disableAllHooks": tr`, "not a JSON object"},
		{filepath.Join(home, ".copilot", "config.json"), "user", "// This file is managed automatically.\n{\"disableAllHooks\": true}", "disableAllHooks"},
	} {
		os.WriteFile(tc.file, []byte(tc.settings), 0o600)
		code, _, errs := run1("-scope", tc.scope, "-dir", repo, "-policy", filepath.Join(repo, "policy.yaml"))
		if code != 1 || !strings.Contains(errs, tc.want) || !strings.Contains(errs, tc.file) {
			t.Errorf("%s: exit %d, %s", tc.file, code, errs)
		}
		os.Remove(tc.file)
	}
	for _, args := range [][]string{
		{"-scope", "user", "-lock"},
		{"-scope", "local"},
		{"-scope", "user", "-deadline", "14s"},             // a timed-out Copilot hook fails open
		{"-scope", "project", "-dir", t.TempDir()},         // policy outside the project
		{"-scope", "managed", "-managed-dir", t.TempDir()}, // unsigned without -allow-unsigned
	} {
		if code, _, _ := run1(args...); code == 0 {
			t.Errorf("%v: accepted", args)
		}
	}
}

func TestApplyCursor(t *testing.T) {
	home := t.TempDir()
	env := func(k string) string { return map[string]string{"HOME": home}[k] }
	run1 := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := run(append([]string{"apply", "-agent", "cursor", "-policy", baseline}, args...), strings.NewReader(""), &out, &errb, env)
		return code, out.String(), errb.String()
	}
	// The user's own hooks stay, and applying twice adds nothing: five
	// events and the briefing (baseline has one)
	hooks := filepath.Join(home, ".cursor", "hooks.json")
	os.MkdirAll(filepath.Dir(hooks), 0o755)
	os.WriteFile(hooks, []byte(`{"version":1,"hooks":{"afterFileEdit":[{"command":"./fmt.sh"}]}}`), 0o644)
	for range 2 {
		if code, out, errs := run1("-scope", "user", "-write", "-command", "/usr/local/bin/cyberboar"); code != 0 || !strings.Contains(out, "failClosed") {
			t.Fatalf("user scope: exit %d %s %s", code, out, errs)
		}
	}
	got, err := os.ReadFile(hooks)
	if err != nil || !strings.Contains(string(got), "./fmt.sh") || strings.Count(string(got), "'--agent' 'cursor'") != 6 {
		t.Fatalf("hooks.json: %v %s", err, got)
	}

	proj := t.TempDir()
	os.MkdirAll(filepath.Join(proj, ".cyberboar"), 0o755)
	pol := filepath.Join(proj, ".cyberboar", "policy.yaml")
	data, _ := os.ReadFile(baseline)
	os.WriteFile(pol, data, 0o644)
	var out, errb bytes.Buffer
	if code := run([]string{"apply", "-agent", "cursor", "-policy", pol, "-scope", "project", "-dir", proj, "-write"}, strings.NewReader(""), &out, &errb, env); code != 0 {
		t.Fatalf("project scope: %s", errb.String())
	}
	got, _ = os.ReadFile(filepath.Join(proj, ".cursor", "hooks.json"))
	if !strings.Contains(string(got), `"'cyberboar' 'hook' '--agent' 'cursor' '--policy' '.cyberboar/policy.yaml'`) {
		t.Errorf("project hooks.json:\n%s", got)
	}

	for _, args := range [][]string{
		{"-scope", "user", "-lock"},
		{"-scope", "local"},
		{"-scope", "user", "-deadline", "14s"},
		{"-scope", "project", "-dir", t.TempDir()},
		{"-scope", "managed", "-managed-dir", t.TempDir()},
		{"-scope", "user", "-command", "https://evil.test/cyberboar"}, // Cursor would drop the whole file
	} {
		if code, _, _ := run1(args...); code == 0 {
			t.Errorf("%v: accepted", args)
		}
	}
	os.WriteFile(hooks, []byte("not json"), 0o644)
	if code, _, _ := run1("-scope", "user", "-write"); code == 0 {
		t.Error("overwrote a hooks.json it can't read")
	}
	if got, _ := os.ReadFile(hooks); string(got) != "not json" {
		t.Errorf("hooks.json changed: %s", got)
	}
}

func TestApplyWarnsAboutCDPATH(t *testing.T) {
	home := t.TempDir()
	os.WriteFile(filepath.Join(home, ".bashrc"), []byte("export CDPATH=.:~/src\n"), 0o600)
	env := func(k string) string { return map[string]string{"HOME": home}[k] }
	var out bytes.Buffer
	if code := run([]string{"apply", "-policy", baseline, "-scope", "user"}, strings.NewReader(""), &out, &bytes.Buffer{}, env); code != 0 {
		t.Fatal(code)
	}
	if !strings.Contains(out.String(), "WARNING: ~/.bashrc sets CDPATH") {
		t.Errorf("no CDPATH warning:\n%s", out.String())
	}
}

// On an operating system the engine doesn't support, apply refuses to write
// settings: the hook there would deny every call
func TestApplyRefusesUnsupportedPlatform(t *testing.T) {
	dir := t.TempDir()
	var out, errb bytes.Buffer
	h := host{getenv: testEnv, goos: "plan9", now: time.Now}
	code := h.run([]string{"apply", "--policy", baseline, "-scope", "project", "-dir", dir, "-write"}, strings.NewReader(""), &out, &errb)
	if code == 0 || !strings.Contains(errb.String(), "does not support") {
		t.Fatalf("apply -write on an unsupported platform: exit %d, stderr %q", code, errb.String())
	}
	if _, err := os.Stat(filepath.Join(dir, ".claude")); err == nil {
		t.Error("apply wrote settings on an unsupported platform")
	}
}

// The settings keep Claude Code's PowerShell tool on, whose commands the hook
// checks on Windows: they deny no whole tool and mirror the Bash rules
func TestApplyKeepsPowerShell(t *testing.T) {
	for _, os := range []string{"windows", "linux"} {
		home := t.TempDir()
		env := func(k string) string { return map[string]string{"HOME": home}[k] }
		h := host{getenv: env, goos: os, now: time.Now}
		var out, errb bytes.Buffer
		if code := h.run([]string{"apply", "--policy", baseline, "--scope", "user", "--command", "/opt/cyberboar"}, nil, &out, &errb); code != 0 {
			t.Fatalf("%s: apply: exit %d, stderr %q", os, code, errb.String())
		}
		if s := out.String(); strings.Contains(s, `"PowerShell"`) || !strings.Contains(s, `"PowerShell(terraform apply *)"`) || strings.Contains(s, "PowerShell tool") {
			t.Errorf("%s: PowerShell rules or notes:\n%s", os, s)
		}
	}
}

// The hook reads no CYBERBOAR_STATE, so --state is how an install
// names the hook's state directory; apply writes it absolute, since the hook
// refuses a relative one
func TestApplyState(t *testing.T) {
	home := t.TempDir()
	env := func(k string) string { return map[string]string{"HOME": home}[k] }
	want, _ := filepath.Abs("rel-state")
	escaped := strings.ReplaceAll(want, `\`, `\\`) // as JSON writes it on Windows
	for _, agent := range []string{"claude-code", "codex", "copilot-cli", "cursor", "opencode"} {
		var out, errb bytes.Buffer
		code := run([]string{"apply", "-agent", agent, "-policy", baseline, "-scope", "user", "-command", "/opt/cyberboar", "-state", "rel-state"},
			strings.NewReader(""), &out, &errb, env)
		if code != 0 || !strings.Contains(out.String(), "-state") || !strings.Contains(out.String(), want) && !strings.Contains(out.String(), escaped) {
			t.Errorf("%s: exit %d, no -state %s in\n%s%s", agent, code, want, out.String(), errb.String())
		}
		out.Reset()
		run([]string{"apply", "-agent", agent, "-policy", baseline, "-scope", "user", "-command", "/opt/cyberboar"}, strings.NewReader(""), &out, &errb, env)
		if strings.Contains(out.String(), "-state") {
			t.Errorf("%s: -state written without being given:\n%s", agent, out.String())
		}
	}
}
