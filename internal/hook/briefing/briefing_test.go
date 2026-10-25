package briefing_test

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/hook/briefing"
	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/pkg/brand"
)

var update = flag.Bool("update", false, "rewrite golden files")

func load(t *testing.T, data []byte) *policy.Policy {
	t.Helper()
	p, err := policy.Load(data)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The briefing is reviewed as a diff of golden files, like generated settings.
func TestBriefingGolden(t *testing.T) {
	for name, src := range map[string]string{
		"baseline":          filepath.Join("examples", "baseline.yaml"),
		"allow-listed":      filepath.Join("examples", "allow-listed.yaml"),
		"advanced-baseline": filepath.Join("examples", "advanced-baseline.yaml"),
	} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", "..", src))
			if err != nil {
				t.Fatal(err)
			}
			got := briefing.Text(load(t, data))
			path := filepath.Join("testdata", name+".txt")
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run go test -update)", err)
			}
			if got != string(want) {
				t.Errorf("briefing differs from %s (run go test -update and review the diff):\n%s", path, got)
			}
		})
	}
}

func policyWith(session string) []byte {
	return []byte("apiVersion: " + brand.APIVersion + "\nkind: Policy\nmetadata: {name: p}\nspec:\n  files: {deny: [\"**/.env*\"]}\n  session: " + session + "\n")
}

func TestSettings(t *testing.T) {
	if got := briefing.Text(load(t, policyWith("{briefing: {enabled: false}}"))); got != "" {
		t.Errorf("briefing off: got %q", got)
	}
	got := briefing.Text(load(t, policyWith("{tripwire: {maxDenials: 5, window: 90m}, briefing: {message: \"Ask #sec first.\"}}")))
	for _, want := range []string{"After 5 denied calls within 1h30m", "From the policy's authors:\nAsk #sec first.", "do not try another way"} {
		if !strings.Contains(got, want) {
			t.Errorf("briefing lacks %q:\n%s", want, got)
		}
	}
	if got := briefing.Text(load(t, policyWith("{tripwire: {enabled: false}}"))); strings.Contains(got, "locks the session") {
		t.Errorf("tripwire off, but the briefing mentions it:\n%s", got)
	}
}

func TestLongListsAreCut(t *testing.T) {
	var pats []string
	for i := range 40 {
		pats = append(pats, "\"dir"+string(rune('a'+i%26))+strings.Repeat("x", i)+"/**\"")
	}
	p := load(t, []byte("apiVersion: "+brand.APIVersion+"\nkind: Policy\nmetadata: {name: p}\nspec: {files: {deny: ["+strings.Join(pats, ",")+"]}}\n"))
	if got := briefing.Text(p); !strings.Contains(got, "and 25 more") {
		t.Errorf("long list not cut:\n%s", got)
	}
}

func TestSessionStartOutput(t *testing.T) {
	if out := briefing.SessionStartOutput(""); out != nil {
		t.Errorf("empty text: got %q", out)
	}
	var v struct {
		HookSpecificOutput map[string]string `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(briefing.SessionStartOutput("rules"), &v); err != nil {
		t.Fatal(err)
	}
	// Codex's output schema (testdata/codex-schema) allows exactly these two
	// fields, and nothing else at the top level.
	schema, err := os.ReadFile("testdata/codex-schema/session-start.command.output.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Definitions map[string]struct {
			Properties map[string]any `json:"properties"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal(schema, &s); err != nil {
		t.Fatal(err)
	}
	for k := range v.HookSpecificOutput {
		if _, ok := s.Definitions["SessionStartHookSpecificOutputWire"].Properties[k]; !ok {
			t.Errorf("Codex's schema has no hookSpecificOutput.%s", k)
		}
	}
	if len(v.HookSpecificOutput) != 2 || v.HookSpecificOutput["hookEventName"] != "SessionStart" || v.HookSpecificOutput["additionalContext"] != "rules" {
		t.Errorf("output = %+v", v)
	}
}
