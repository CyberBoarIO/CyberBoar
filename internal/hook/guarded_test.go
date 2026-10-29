package hook_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/adapters/codex"
	"cyberboar.dev/cyberboar/internal/engine"
	"cyberboar.dev/cyberboar/internal/hook"
)

// The agent may not switch its own hook off (builtin.guarded), which one
// Edit of .claude/settings.local.json would do.
func TestHookFilesAreGuarded(t *testing.T) {
	home := t.TempDir()
	repo := filepath.Join(home, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := t.TempDir()
	getenv := func(k string) string {
		return map[string]string{"HOME": home, "CLAUDE_PROJECT_DIR": repo, "CLAUDE_CONFIG_DIR": cfg}[k]
	}
	policy := filepath.Join(home, "policy.yaml")
	if err := os.WriteFile(policy, baselinePolicy(t), 0o644); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(home, "keys", "policy.pub")
	run := func(tool, input string) hook.Result {
		in := fmt.Sprintf(`{"hook_event_name":"PreToolUse","tool_name":%q,"cwd":%q,"tool_input":%s}`, tool, repo, input)
		return hook.Run(context.Background(), strings.NewReader(in), hook.Options{Adapter: cc, PolicyPath: policy,
			AuditPath: filepath.Join(home, "audit.jsonl"), Guarded: []string{key}, Getenv: getenv})
	}
	edit := func(p string) string { return fmt.Sprintf(`{"file_path":%q,"old_string":"a","new_string":"b"}`, p) }
	for _, p := range []string{
		filepath.Join(repo, ".claude", "settings.local.json"),
		filepath.Join(repo, ".claude", "settings.json"),
		filepath.Join(home, ".claude", "settings.json"),
		filepath.Join(cfg, "settings.json"),
		policy, policy + ".sig", key,
	} {
		assertDenied(t, run("Edit", edit(p)), engine.RuleGuarded)
	}
	// The audit log is guarded too, but builtin.self, which also covers
	// reading it, is the stricter rule and answers first.
	assertDenied(t, run("Edit", edit(filepath.Join(home, "audit.jsonl"))), engine.RuleSelf)
	assertDenied(t, run("Bash", `{"command":"rm -rf .claude"}`), engine.RuleGuarded)
	if r := run("Read", fmt.Sprintf(`{"file_path":%q}`, filepath.Join(repo, ".claude", "settings.local.json"))); r.Exit != 0 {
		t.Errorf("reading the settings: %+v", r.Verdict)
	}
	if r := run("Edit", edit(filepath.Join(repo, "main.go"))); r.Exit != 0 {
		t.Errorf("editing a project file: %+v", r.Verdict)
	}
}

func TestCodexFilesAreGuarded(t *testing.T) {
	home := t.TempDir()
	repo := filepath.Join(home, "repo")
	getenv := func(k string) string { return map[string]string{"HOME": home}[k] }
	for _, change := range []string{"Add File: .codex/config.toml\n+x", "Delete File: " + filepath.Join(home, ".codex", "hooks.json")} {
		patch := "*** Begin Patch\n*** " + change + "\n*** End Patch\n"
		in := fmt.Sprintf(`{"hook_event_name":"PreToolUse","tool_name":"apply_patch","cwd":%q,"tool_input":{"command":%q}}`, repo, patch)
		r := hook.Run(context.Background(), strings.NewReader(in), hook.Options{Adapter: codex.Adapter{}, PolicyPath: policyFile(t, baselinePolicy(t), nil), Getenv: getenv})
		assertDenied(t, r, engine.RuleGuarded)
	}
}

// A hook that can't tell where its own files are can't guard them.
func TestUnlocatableHookFilesDeny(t *testing.T) {
	policy := policyFile(t, baselinePolicy(t), nil)
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Getwd(); err == nil {
		t.Skip("the working directory is still reachable after removal on this system")
	}
	r := hook.Run(context.Background(), strings.NewReader(bashLS), hook.Options{Adapter: cc, PolicyPath: policy,
		Guarded: []string{"settings.json"}, Getenv: env})
	assertDenied(t, r, hook.RuleGuardedPath)
}
