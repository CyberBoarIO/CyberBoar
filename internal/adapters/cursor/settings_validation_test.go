package cursor_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/adapters/cursor"
)

func TestSettingsRequireOneObject(t *testing.T) {
	merge := func(existing []byte) ([]byte, error) {
		return cursor.MergeHooks(existing, cursor.FragmentOptions{Command: "cyberboar", Policy: "p.yaml", Deadline: "5s"})
	}
	for _, existing := range []string{
		"null", "[]", "1", `"settings"`, "{", "{} {}", "{} null", "{} garbage", "{} {",
	} {
		t.Run(existing, func(t *testing.T) {
			if out, err := merge([]byte(existing)); err == nil || out != nil {
				t.Fatalf("accepted invalid settings %q: output %s, error %v", existing, out, err)
			}
		})
	}
	for _, existing := range []string{"", " \n\t", `{}`, "{} \n\t"} {
		if _, err := merge([]byte(existing)); err != nil {
			t.Errorf("valid settings %q: %v", existing, err)
		}
	}
	out, err := merge([]byte(`{"unknown":{"number":9007199254740993,"fraction":1e3}}`))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Unknown map[string]json.RawMessage `json:"unknown"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if string(doc.Unknown["number"]) != "9007199254740993" || string(doc.Unknown["fraction"]) != "1e3" {
		t.Fatalf("unknown settings or number representations changed: %s", out)
	}
}

func TestMergeRejectsMalformedRetainedHooks(t *testing.T) {
	for _, tc := range []struct {
		name, event, definition, path string
	}{
		{"event is object", "afterFileEdit", `{"command":"./format.sh"}`, "hooks.afterFileEdit"},
		{"event is null", "preToolUse", `null`, "hooks.preToolUse"},
		{"entry is boolean", "preToolUse", `[false]`, "hooks.preToolUse[0]"},
		{"entry is null", "afterFileEdit", `[null]`, "hooks.afterFileEdit[0]"},
		{"entry is array", "afterFileEdit", `[[]]`, "hooks.afterFileEdit[0]"},
		{"command missing", "preToolUse", `[{}]`, "hooks.preToolUse[0].command"},
		{"command is number", "preToolUse", `[{"command":7}]`, "hooks.preToolUse[0].command"},
		{"command is null", "afterFileEdit", `[{"command":null}]`, "hooks.afterFileEdit[0].command"},
		{"command is blank", "afterFileEdit", `[{"command":"  "}]`, "hooks.afterFileEdit[0].command"},
		{"type is number", "preToolUse", `[{"type":1,"command":"./hook.sh"}]`, "hooks.preToolUse[0].type"},
		{"type is empty", "preToolUse", `[{"type":"","command":"./hook.sh"}]`, "hooks.preToolUse[0].type"},
		{"type is unknown", "preToolUse", `[{"type":"shell","command":"./hook.sh"}]`, "hooks.preToolUse[0].type"},
		{"prompt missing", "preToolUse", `[{"type":"prompt"}]`, "hooks.preToolUse[0].prompt"},
		{"prompt is number", "preToolUse", `[{"type":"prompt","prompt":7}]`, "hooks.preToolUse[0].prompt"},
		{"prompt is blank", "preToolUse", `[{"type":"prompt","prompt":""}]`, "hooks.preToolUse[0].prompt"},
		{"timeout is string", "afterFileEdit", `[{"command":"./hook.sh","timeout":"15"}]`, "hooks.afterFileEdit[0].timeout"},
		{"timeout is null", "afterFileEdit", `[{"command":"./hook.sh","timeout":null}]`, "hooks.afterFileEdit[0].timeout"},
		{"failClosed is string", "preToolUse", `[{"command":"./hook.sh","failClosed":"true"}]`, "hooks.preToolUse[0].failClosed"},
		{"matcher is array", "preToolUse", `[{"command":"./hook.sh","matcher":[]}]`, "hooks.preToolUse[0].matcher"},
		{"model is object", "preToolUse", `[{"type":"prompt","prompt":"Check","model":{}}]`, "hooks.preToolUse[0].model"},
		{"loop limit is string", "stop", `[{"command":"./hook.sh","loop_limit":"5"}]`, "hooks.stop[0].loop_limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			existing := []byte(`{"version":1,"hooks":{"` + tc.event + `":` + tc.definition + `}}`)
			out, err := cursor.MergeHooks(existing, cursor.FragmentOptions{Command: "cyberboar", Policy: "p.yaml", Deadline: "5s"})
			if err == nil || out != nil || !strings.Contains(err.Error(), tc.path) {
				t.Fatalf("got %d output bytes, error %v; want rejection naming %s", len(out), err, tc.path)
			}
		})
	}
}

func TestMergePreservesRetainedHooks(t *testing.T) {
	existing := []byte(`{"version":1,"hooks":{
  "preToolUse":[
    {"type":"prompt","prompt":"Allow read-only commands","model":"fast","matcher":"Shell","timeout":2.5,"failClosed":true,"extra":{"number":9007199254740993}},
    {"type":"prompt","prompt":"Check this call","command":"'echo' 'hook' '--agent' 'cursor'"}
  ],
  "afterFileEdit":[{"command":"./format.sh","timeout":1e3,"loop_limit":null,"extra":{"enabled":true}}],
  "stop":[{"type":"command","command":"./stop.sh","loop_limit":5}],
  "futureEvent":[{"command":"./future.sh","future_option":{"number":9007199254740993}}]
}}`)
	o := cursor.FragmentOptions{Command: "cyberboar", Policy: "p.yaml", Deadline: "5s"}
	out, err := cursor.MergeHooks(existing, o)
	if err != nil {
		t.Fatal(err)
	}
	decode := func(data []byte) map[string][]map[string]any {
		t.Helper()
		var doc struct {
			Hooks map[string][]map[string]any `json:"hooks"`
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			t.Fatal(err)
		}
		return doc.Hooks
	}
	before, after := decode(existing), decode(out)
	for event, entries := range before {
		for _, want := range entries {
			found := false
			for _, got := range after[event] {
				found = found || reflect.DeepEqual(got, want)
			}
			if !found {
				t.Errorf("a retained %s hook was lost or changed", event)
			}
		}
	}
	again, err := cursor.MergeHooks(out, o)
	if err != nil || !bytes.Equal(out, again) {
		t.Fatalf("applying twice changed the merged file: %v", err)
	}
}

// An earlier CyberBoar entry is replaced however its command is quoted, and
// commands that only mention the words are kept.
func TestMergeReplacesManualEntries(t *testing.T) {
	existing := []byte(`{"version":1,"hooks":{"preToolUse":[
  {"command":"cyberboar hook --agent cursor --policy .cyberboar/policy.yaml --deadline 5s","timeout":15,"failClosed":true},
  {"command":"/opt/bin/cyberboar \"hook\" --agent=cursor --policy p.yaml"},
  {"command":"./audit.sh hook --agent claude"},
  {"command":"echo 'hook --agent cursor'"}
]}}`)
	out, err := cursor.MergeHooks(existing, cursor.FragmentOptions{Command: "cyberboar", Policy: "p.yaml", Deadline: "5s"})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Hooks map[string][]map[string]any `json:"hooks"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	var cmds []string
	for _, h := range doc.Hooks["preToolUse"] {
		cmds = append(cmds, h["command"].(string))
	}
	want := []string{"'cyberboar' 'hook' '--agent' 'cursor' '--policy' 'p.yaml' '--deadline' '5s'", "./audit.sh hook --agent claude", "echo 'hook --agent cursor'"}
	if !reflect.DeepEqual(cmds, want) {
		t.Errorf("preToolUse commands %q, want %q", cmds, want)
	}
}
