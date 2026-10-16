package codex_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/adapters/codex"
)

func TestSettingsRequireOneObject(t *testing.T) {
	merge := func(existing []byte) ([]byte, error) {
		return codex.MergeHooksJSON(existing, codex.FragmentOptions{Command: "cyberboar", Policy: "p.yaml", Deadline: "5s"})
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

func TestMergeRejectsMalformedHooks(t *testing.T) {
	for _, tc := range []struct{ name, existing, path string }{
		{"hooks boolean", `{"hooks":true}`, "hooks"},
		{"hooks null", `{"hooks":null}`, "hooks"},
		{"event object", `{"hooks":{"PreToolUse":{}}}`, "hooks.PreToolUse"},
		{"event null", `{"hooks":{"Stop":null}}`, "hooks.Stop"},
		{"group boolean", `{"hooks":{"PreToolUse":[false]}}`, "hooks.PreToolUse[0]"},
		{"matcher number", `{"hooks":{"Stop":[{"matcher":7,"hooks":[]}]}}`, "hooks.Stop[0].matcher"},
		{"handlers missing", `{"hooks":{"Stop":[{}]}}`, "hooks.Stop[0].hooks"},
		{"handlers object", `{"hooks":{"Stop":[{"hooks":{}}]}}`, "hooks.Stop[0].hooks"},
		{"handler null", `{"hooks":{"Stop":[{"hooks":[null]}]}}`, "hooks.Stop[0].hooks[0]"},
		{"type missing", `{"hooks":{"Stop":[{"hooks":[{"command":"./check.sh"}]}]}}`, ".type"},
		{"type unknown", `{"hooks":{"Stop":[{"hooks":[{"type":"shell","command":"./check.sh"}]}]}}`, ".type"},
		{"command number", `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":7}]}]}}`, ".command"},
		{"command blank", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":" "}]}]}}`, ".command"},
		{"timeout string", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"./check.sh","timeout":"3"}]}]}}`, ".timeout"},
		{"status object", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"./check.sh","statusMessage":{}}]}]}}`, ".statusMessage"},
		{"windows command number", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"./check.sh","commandWindows":7}]}]}}`, ".commandWindows"},
		{"async string", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"./check.sh","async":"true"}]}]}}`, ".async"},
		{"context limit string", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"./check.sh","additionalContextLimit":"100"}]}]}}`, ".additionalContextLimit"},
		{"mcp server missing", `{"hooks":{"PostToolUse":[{"hooks":[{"type":"mcp_tool","tool":"check"}]}]}}`, ".server"},
		{"mcp tool missing", `{"hooks":{"PostToolUse":[{"hooks":[{"type":"mcp_tool","server":"scanner"}]}]}}`, ".tool"},
		{"mcp input list", `{"hooks":{"PostToolUse":[{"hooks":[{"type":"mcp_tool","server":"scanner","tool":"check","input":[]}]}]}}`, ".input"},
		{"prompt missing", `{"hooks":{"Stop":[{"hooks":[{"type":"prompt"}]}]}}`, ".prompt"},
		{"agent prompt number", `{"hooks":{"Stop":[{"hooks":[{"type":"agent","prompt":7}]}]}}`, ".prompt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := codex.MergeHooksJSON([]byte(tc.existing), codex.FragmentOptions{Command: "cyberboar", Policy: "p.yaml", Deadline: "5s"})
			if err == nil || out != nil || !strings.Contains(err.Error(), tc.path) {
				t.Fatalf("got %d output bytes, error %v; want rejection naming %s", len(out), err, tc.path)
			}
		})
	}
}

func TestMergePreservesValidHooks(t *testing.T) {
	existing := []byte(`{"description":"team hooks","unknown":{"number":9007199254740993},"hooks":{
  "PreToolUse":[{"matcher":"Bash","extra":true,"hooks":[{"type":"command","command":"./check.sh","commandWindows":"check.ps1","timeout":1e3,"async":false,"additionalContextLimit":5000,"statusMessage":"Checking","unknown":{"number":9007199254740993}}]}],
  "PostToolUse":[{"hooks":[{"type":"mcp_tool","server":"scanner","tool":"check","input":{"patch":"${tool_input.command}","extra":[true,9007199254740993]},"timeout":30}]}],
  "Stop":[{"hooks":[{"type":"prompt","prompt":"Check the result","model":"fast"},{"type":"agent","prompt":"Review the work"}]}],
  "FutureEvent":[{"matcher":null,"hooks":[{"type":"command","command":"./future.sh","statusMessage":null}]}]
}}`)
	o := codex.FragmentOptions{Command: "cyberboar", Policy: "p.yaml", Deadline: "5s"}
	out, err := codex.MergeHooksJSON(existing, o)
	if err != nil {
		t.Fatal(err)
	}
	decode := func(data []byte) map[string]any {
		t.Helper()
		var doc map[string]any
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	before, after := decode(existing), decode(out)
	for key, want := range before {
		if key == "hooks" {
			for event, groups := range want.(map[string]any) {
				got := after[key].(map[string]any)[event].([]any)
				if event == "PreToolUse" {
					got = got[:len(got)-1]
				}
				if !reflect.DeepEqual(got, groups) {
					t.Errorf("retained %s groups changed", event)
				}
			}
		} else if !reflect.DeepEqual(want, after[key]) {
			t.Errorf("retained %s changed", key)
		}
	}
	again, err := codex.MergeHooksJSON(out, o)
	if err != nil || !bytes.Equal(out, again) {
		t.Fatalf("applying twice changed the merged file: %v", err)
	}
}
