package codex

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
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

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "apply", name)
	if *update {
		os.MkdirAll(filepath.Dir(path), 0o755)
		os.WriteFile(path, got, 0o644)
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update)", err)
	}
	if string(got) != string(want) {
		t.Errorf("output differs from %s (run go test -update and review the diff):\n%s", name, got)
	}
}

// Generated configuration is reviewed as diffs of golden files
func TestRequirementsGolden(t *testing.T) {
	out, notes := Requirements(loadPolicy(t, "baseline.yaml"), FragmentOptions{Scope: ScopeManaged,
		Command: "/usr/local/bin/cyberboar", Policy: "/etc/cyberboar/policy.yaml", Audit: "/var/log/cyberboar/audit.jsonl",
		Deadline: "5s", Lock: true})
	golden(t, "baseline-requirements.toml", append(out, []byte("\n# notes:\n# "+strings.Join(notes, "\n# ")+"\n")...))
}

func TestHooksJSONGolden(t *testing.T) {
	existing := []byte(`{"description":"team hooks","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"./lint.sh"}]}],"Stop":[]}}`)
	o := FragmentOptions{Scope: ScopeProject, Command: "cyberboar", Policy: ".cyberboar/policy.yaml", Deadline: "5s"}
	out, err := MergeHooksJSON(existing, o)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "project-hooks.json", out)

	// Applying again replaces CyberBoar's handler instead of adding a second
	again, err := MergeHooksJSON(out, o)
	if err != nil || string(again) != string(out) {
		t.Errorf("apply is not idempotent:\n%s", again)
	}
}

func TestMergeHooksJSONRejectsNonObject(t *testing.T) {
	if _, err := MergeHooksJSON([]byte(`[1]`), FragmentOptions{}); err == nil {
		t.Error("a hooks.json that isn't an object was accepted")
	}
	var v map[string]any
	out, _ := MergeHooksJSON(nil, FragmentOptions{Command: "/bin/cb", Policy: "/p", Deadline: "5s"})
	if json.Unmarshal(out, &v) != nil {
		t.Error("output is not JSON")
	}
}

func TestHookCommandQuoting(t *testing.T) {
	got := HookCommand(FragmentOptions{Command: "/opt/my tools/cb", Policy: "/p/it's.yaml", Deadline: "5s"})
	want := `'/opt/my tools/cb' hook --agent codex --policy '/p/it'\''s.yaml' --deadline '5s'`
	if got != want {
		t.Errorf("HookCommand = %s", got)
	}
}

// On Windows the line must work in PowerShell, where a quoted first word is a
// string, and in cmd.exe, which has no call operator: the program goes bare
func TestHookCommandWindows(t *testing.T) {
	o := FragmentOptions{Scope: ScopeUser, Command: `C:\Users\Łukasz\cb\cyberboar.exe`, Policy: `C:\my policies\p.yaml`, Deadline: "5s", Windows: true}
	got := HookCommand(o)
	want := `C:\Users\Łukasz\cb\cyberboar.exe hook --agent codex --policy "C:\my policies\p.yaml" --deadline "5s"`
	if got != want || CheckWindows(o) != nil {
		t.Errorf("HookCommand = %s (%v)", got, CheckWindows(o))
	}
	for _, program := range []string{`C:\Program Files\cb.exe`, `"C:\cb.exe"`, `C:\a&b\cb.exe`, `C:\$x\cb.exe`, `C:\(x)\cb.exe`, `C:\a'b\cb.exe`} {
		if o := (FragmentOptions{Scope: ScopeUser, Command: program, Policy: `C:\p.yaml`, Deadline: "5s", Windows: true}); CheckWindows(o) == nil {
			t.Errorf("program %s accepted", program)
		}
	}
	if !BareWindowsProgram(`C:\PROGRA~1\CYBERB~1\CYBERB~1.EXE`) {
		t.Error("an 8.3 short path refused")
	}
}

func TestTOMLString(t *testing.T) {
	if got := tomlString("a\"b\\c\nd\x7f"); got != `"a\"b\\c\u000Ad\u007F"` {
		t.Errorf("tomlString = %s", got)
	}
}

// The briefing adds a SessionStart handler next to the user's own, and an
// apply with the briefing off removes it again
func TestMergeHooksJSONBriefing(t *testing.T) {
	existing := []byte(`{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"./motd.sh"}]}]}}`)
	on := FragmentOptions{Scope: ScopeUser, Command: "/bin/cb", Policy: "/p.yaml", PubKey: "/k.pub", Deadline: "5s", Briefing: true}
	out, err := MergeHooksJSON(existing, on)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Hooks map[string][]struct {
			Hooks []map[string]any `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	start := doc.Hooks["SessionStart"]
	if len(start) != 2 || start[0].Hooks[0]["command"] != "./motd.sh" ||
		start[1].Hooks[0]["command"] != "'/bin/cb' brief --agent codex --policy '/p.yaml' --pubkey '/k.pub'" {
		t.Fatalf("SessionStart = %+v", start)
	}
	if again, _ := MergeHooksJSON(out, on); string(again) != string(out) {
		t.Errorf("apply is not idempotent:\n%s", again)
	}

	off := on
	off.Briefing = false
	out, _ = MergeHooksJSON(out, off)
	if strings.Contains(string(out), " brief ") || !strings.Contains(string(out), "./motd.sh") {
		t.Errorf("briefing off:\n%s", out)
	}
	// An event that only held CyberBoar's briefing goes away
	out, _ = MergeHooksJSON(nil, on)
	if out, _ = MergeHooksJSON(out, off); strings.Contains(string(out), "SessionStart") {
		t.Errorf("empty SessionStart left behind:\n%s", out)
	}
}
