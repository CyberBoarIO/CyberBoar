package claudecode

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/policy"
)

var update = flag.Bool("update", false, "rewrite golden files")

func loadPolicy(t *testing.T, name string) *policy.Policy {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "examples", name))
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Load(data)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Generated settings are reviewed as diffs of these golden files
func TestFragmentGolden(t *testing.T) {
	for _, tc := range []struct {
		golden, policy string
		opts           FragmentOptions
	}{
		{"baseline-managed.json", "baseline.yaml", FragmentOptions{Scope: ScopeManaged, Command: "/usr/local/bin/cyberboar",
			Policy: "/etc/cyberboar/policy.yaml", Audit: "/var/log/cyberboar/audit.jsonl", Deadline: "5s", Lock: true}},
		{"allow-listed-project.json", "allow-listed.yaml", FragmentOptions{Scope: ScopeProject, Command: "cyberboar",
			Policy: "${CLAUDE_PROJECT_DIR}/.cyberboar/policy.yaml", Deadline: "5s"}},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			f := BuildFragment(loadPolicy(t, tc.policy), tc.opts)
			got, err := Marshal(map[string]any{"settings": f.Settings, "notes": f.Notes})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", "apply", tc.golden)
			if *update {
				os.WriteFile(path, got, 0o644)
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run go test -update)", err)
			}
			if string(got) != string(want) {
				t.Errorf("fragment differs from %s (run go test -update and review the diff):\n%s", tc.golden, got)
			}
		})
	}
}

func TestNativePath(t *testing.T) {
	for _, tc := range []struct {
		pat   string
		scope Scope
		want  string
	}{
		{"/etc/shadow", ScopeUser, "//etc/shadow"},
		{"~/.ssh/**", ScopeUser, "~/.ssh/**"},
		{"**/.env*", ScopeProject, "//**/.env*"},
		{"secrets/**", ScopeProject, "/secrets/**"},
		{"secrets/**", ScopeLocal, "/secrets/**"},
		{"secrets/**", ScopeUser, "secrets/**"}, // "/secrets/**" would mean ~/.claude/secrets in user settings
	} {
		if got := nativePath(tc.pat, tc.scope); got != tc.want {
			t.Errorf("nativePath(%q, %s) = %q, want %q", tc.pat, tc.scope, got, tc.want)
		}
	}
}

func TestNativeFile(t *testing.T) {
	for _, tc := range []struct{ path, want string }{
		{"/usr/local/bin/cyberboar", "//usr/local/bin/cyberboar"},
		{"${CLAUDE_PROJECT_DIR}/.cyberboar/policy.yaml", "/.cyberboar/policy.yaml"},
		{`C:\Users\dev\bin\cyberboar.exe`, "//c/Users/dev/bin/cyberboar.exe"},
		{"D:/keys/policy.pub", "//d/keys/policy.pub"},
		{"cyberboar", ""}, // a command on PATH
		{"", ""},
	} {
		if got, _ := nativeFile(tc.path); got != tc.want {
			t.Errorf("nativeFile(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// Every scope keeps Claude's file tools off the settings files that install
// the hook, whatever the policy says
func TestGuardRulesInEveryScope(t *testing.T) {
	p, err := policy.Load([]byte("apiVersion: cyberboar.dev/v1\nkind: Policy\nmetadata: {name: empty}\nspec: {commands: {denyInterpreters: false}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []Scope{ScopeUser, ScopeProject, ScopeLocal, ScopeManaged} {
		f := BuildFragment(p, FragmentOptions{Scope: scope, Command: "/opt/cyberboar", Policy: "/etc/policy.yaml", Deadline: "5s"})
		deny, _ := f.Settings["permissions"].(map[string]any)["deny"].([]any)
		for _, want := range []string{"Edit(//**/.claude/settings.json)", "Edit(//**/.claude/settings.local.json)",
			"Edit(//**/.claude/agents/**)", "Edit(//**/.claude/skills/**)", "Edit(//**/.claude/commands/**)",
			"Edit(//**/.claude/plugins/**)", "Edit(//etc/policy.yaml)", "Edit(//opt/cyberboar)"} {
			if !slices.Contains(deny, any(want)) {
				t.Errorf("%s scope: no %s in %v", scope, want, deny)
			}
		}
	}
}

func TestMerge(t *testing.T) {
	frag := BuildFragment(loadPolicy(t, "baseline.yaml"), FragmentOptions{Scope: ScopeUser,
		Command: "/opt/bin/cyberboar", Policy: "/p.yaml", Deadline: "5s"}).Settings

	existing := `{
  "model": "opus",
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/lint-hook"}]},
      {"matcher": "*", "hooks": [{"type": "command", "command": "/old/path/cyberboar", "args": ["hook", "--policy", "/old.yaml"]}]}
    ],
    "Stop": [{"hooks": [{"type": "command", "command": "notify"}]}],
    "Notification": [{"matcher": "x", "hooks": [{"type": "command", "command": "notify-team"}]}],
    "PostToolUse": []
  },
  "permissions": {"deny": ["Bash(rm -rf *)", "Read(~/.ssh/**)"], "allow": ["Bash(npm test *)"]}
}`
	out, err := Merge([]byte(existing), frag)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{`"model": "opus"`, "lint-hook", `"Stop"`, "/opt/bin/cyberboar", `"Bash(npm test *)"`, `"Bash(rm -rf *)"`, `"Bash(terraform apply *)"`} {
		if !strings.Contains(s, want) {
			t.Errorf("merged settings lost or lack %s:\n%s", want, s)
		}
	}
	for _, gone := range []string{"/old/path/cyberboar", "/old.yaml", "null"} {
		if strings.Contains(s, gone) {
			t.Errorf("merged settings still contain the previous hook (%s):\n%s", gone, s)
		}
	}
	if strings.Count(s, `"Read(~/.ssh/**)"`) != 1 {
		t.Errorf("duplicate permission rule:\n%s", s)
	}
	again, err := Merge(out, frag)
	if err != nil || string(again) != s {
		t.Errorf("merge is not idempotent:\n%s", again)
	}
	if _, err := Merge([]byte("[1, 2]"), frag); err == nil {
		t.Error("merging into a non-object must fail")
	}
	if _, err := Merge([]byte("null"), frag); err == nil || strings.Contains(err.Error(), "<nil>") {
		t.Errorf("merging into null: %v", err)
	}
	if _, err := Merge([]byte("{broken"), frag); err == nil {
		t.Error("merging into invalid JSON must fail")
	}
}

// Claude Code runs no hook while settings set disableAllHooks, so merging
// the hook into such settings is refused rather than reported as done
// The key is the user's setting and is not removed behind their back
func TestMergeRefusesHooksSwitchedOff(t *testing.T) {
	frag := BuildFragment(loadPolicy(t, "baseline.yaml"), FragmentOptions{Scope: ScopeUser,
		Command: "/opt/bin/cyberboar", Policy: "/p.yaml", Deadline: "5s"}).Settings
	for _, existing := range []string{`{"disableAllHooks": true, "model": "opus"}`, `{"disableAllHooks": "true"}`, `{"disableAllHooks": 1}`} {
		if out, err := Merge([]byte(existing), frag); err == nil || !strings.Contains(err.Error(), "disableAllHooks") {
			t.Errorf("Merge(%s) = %s, %v; want an error naming disableAllHooks", existing, out, err)
		}
	}
	for _, existing := range []string{`{"disableAllHooks": false}`, `{"disableAllHooks": null}`} {
		if _, err := Merge([]byte(existing), frag); err != nil {
			t.Errorf("Merge(%s): %v", existing, err)
		}
	}
}

// The briefing is a SessionStart handler; turning it off in the policy and
// applying again removes CyberBoar's handler and keeps the user's
func TestMergeBriefing(t *testing.T) {
	p := loadPolicy(t, "baseline.yaml")
	o := FragmentOptions{Scope: ScopeUser, Command: "/opt/bin/cyberboar", Policy: "/p.yaml", PubKey: "/k.pub", Deadline: "5s"}
	existing := `{"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "direnv-hook"}]}]}}`
	out, err := Merge([]byte(existing), BuildFragment(p, o).Settings)
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Hooks map[string][]struct {
			Hooks []map[string]any `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(out, &s); err != nil {
		t.Fatal(err)
	}
	starts := s.Hooks["SessionStart"]
	if len(starts) != 2 || starts[0].Hooks[0]["command"] != "direnv-hook" ||
		fmt.Sprint(starts[1].Hooks[0]["args"]) != "[brief --policy /p.yaml --pubkey /k.pub]" {
		t.Fatalf("SessionStart after apply: %+v", starts)
	}

	off := *p
	disabled := false
	off.Spec.Session.Briefing.Enabled = &disabled
	out, err = Merge(out, BuildFragment(&off, o).Settings)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), `"brief"`) || !strings.Contains(string(out), "direnv-hook") {
		t.Fatalf("briefing off: CyberBoar's handler must go, the user's stay:\n%s", out)
	}
	out, err = Merge([]byte(`{"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "/x/cyberboar", "args": ["brief"]}]}]}}`), BuildFragment(&off, o).Settings)
	if err != nil || strings.Contains(string(out), "SessionStart") {
		t.Fatalf("an event left empty must be removed: %s %v", out, err)
	}
}

func TestManagedDir(t *testing.T) {
	for goos, want := range map[string]string{
		"linux": "/etc/claude-code", "darwin": "/Library/Application Support/ClaudeCode", "windows": `C:\Program Files\ClaudeCode`,
	} {
		if got := ManagedDir(goos); got != want {
			t.Errorf("ManagedDir(%s) = %q, want %q", goos, got, want)
		}
	}
}

// A deny rule naming the whole PowerShell tool removes it from Claude's
// context, so the agent never reaches for it, and holds even when the hook can't run
// It is there whatever the policy says
func TestFragmentDeniesPowerShell(t *testing.T) {
	for _, name := range []string{"baseline.yaml", "allow-listed.yaml"} {
		p := loadPolicy(t, name)
		for _, interp := range []bool{true, false} {
			p.Spec.Commands.DenyInterpreters = &interp
			f := BuildFragment(p, FragmentOptions{Scope: ScopeUser, Command: "cyberboar", Policy: "/p.yaml", Deadline: "5s"})
			perms, _ := f.Settings["permissions"].(map[string]any)
			deny, _ := perms["deny"].([]any)
			if !slices.Contains(deny, any("PowerShell")) {
				t.Errorf("%s, denyInterpreters %v: no native PowerShell deny in %v", name, interp, deny)
			}
		}
	}
}
