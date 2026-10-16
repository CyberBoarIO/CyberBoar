package claudecode

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestMergeRejectsMalformedSettings(t *testing.T) {
	frag := BuildFragment(loadPolicy(t, "baseline.yaml"), FragmentOptions{Scope: ScopeUser,
		Command: "/opt/bin/cyberboar", Policy: "/p.yaml", Deadline: "5s"}).Settings
	for _, tc := range []struct{ name, existing, path string }{
		{"hooks boolean", `{"hooks":true}`, "hooks"},
		{"hooks null", `{"hooks":null}`, "hooks"},
		{"event object", `{"hooks":{"PreToolUse":{}}}`, "hooks.PreToolUse"},
		{"group boolean", `{"hooks":{"PreToolUse":[false]}}`, "hooks.PreToolUse[0]"},
		{"matcher number", `{"hooks":{"Stop":[{"matcher":7,"hooks":[]}]}}`, ".matcher"},
		{"handlers missing", `{"hooks":{"Stop":[{}]}}`, ".hooks"},
		{"handler null", `{"hooks":{"Stop":[{"hooks":[null]}]}}`, ".hooks[0]"},
		{"handler type missing", `{"hooks":{"Stop":[{"hooks":[{"command":"check"}]}]}}`, ".type"},
		{"command number", `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":7}]}]}}`, ".command"},
		{"command blank", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":" "}]}]}}`, ".command"},
		{"args string", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"check","args":"arg"}]}]}}`, ".args"},
		{"args number", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"check","args":[7]}]}]}}`, ".args[0]"},
		{"timeout string", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"check","timeout":"3"}]}]}}`, ".timeout"},
		{"async string", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"check","async":"true"}]}]}}`, ".async"},
		{"failure mode invalid", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"check","onFailure":"ignore"}]}]}}`, ".onFailure"},
		{"http url missing", `{"hooks":{"Stop":[{"hooks":[{"type":"http"}]}]}}`, ".url"},
		{"headers number", `{"hooks":{"Stop":[{"hooks":[{"type":"http","url":"https://example.com/hook","headers":{"X-Label":7}}]}]}}`, ".headers.X-Label"},
		{"mcp server missing", `{"hooks":{"Stop":[{"hooks":[{"type":"mcp_tool","tool":"check"}]}]}}`, ".server"},
		{"prompt missing", `{"hooks":{"Stop":[{"hooks":[{"type":"prompt"}]}]}}`, ".prompt"},
		{"permissions boolean", `{"permissions":true}`, "permissions"},
		{"permissions null", `{"permissions":null}`, "permissions"},
		{"deny string", `{"permissions":{"deny":"Read(~/.ssh/**)"}}`, "permissions.deny"},
		{"deny boolean", `{"permissions":{"deny":[false]}}`, "permissions.deny[0]"},
		{"allow object", `{"permissions":{"allow":{}}}`, "permissions.allow"},
		{"ask null entry", `{"permissions":{"ask":[null]}}`, "permissions.ask[0]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := Merge([]byte(tc.existing), frag)
			if err == nil || out != nil || !strings.Contains(err.Error(), tc.path) {
				t.Fatalf("got %d output bytes, error %v; want rejection naming %s", len(out), err, tc.path)
			}
		})
	}
}

func TestMergePreservesValidSettings(t *testing.T) {
	existing := []byte(`{"unknown":{"number":9007199254740993,"fraction":1e3},"hooks":{
  "PreToolUse":[{"matcher":"Bash","extra":true,"hooks":[{"type":"command","command":"./check.sh","args":["a b",""],"timeout":1e3,"onFailure":"block","async":false,"unknown":{"number":9007199254740993}}]}],
  "PostToolUse":[{"hooks":[{"type":"mcp_tool","server":"scanner","tool":"check","input":{"path":"${tool_input.file_path}","extra":[true,9007199254740993]}}]}],
  "Stop":[{"hooks":[{"type":"http","url":"https://example.com/hook","headers":{"X-Label":"value"},"allowedEnvVars":["LABEL"],"onFailure":"continue"},{"type":"prompt","prompt":"Check the result","model":"fast"},{"type":"agent","prompt":"Review the work"}]}],
  "FutureEvent":[{"hooks":[{"type":"command","command":"./future.sh","future_option":{"number":9007199254740993}}]}]
},"permissions":{"allow":["Bash(npm test *)"],"deny":["Read(private/**)"],"ask":["Bash(publish *)"],"unknown":{"number":9007199254740993}}}`)
	frag := BuildFragment(loadPolicy(t, "baseline.yaml"), FragmentOptions{Scope: ScopeUser,
		Command: "/opt/bin/cyberboar", Policy: "/p.yaml", Deadline: "5s"}).Settings
	out, err := Merge(existing, frag)
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
	if !reflect.DeepEqual(before["unknown"], after["unknown"]) {
		t.Error("unknown top-level properties changed")
	}
	for event, value := range before["hooks"].(map[string]any) {
		got := after["hooks"].(map[string]any)[event].([]any)
		want := value.([]any)
		if len(got) < len(want) || !reflect.DeepEqual(got[:len(want)], want) {
			t.Errorf("retained %s groups changed", event)
		}
	}
	for field, want := range before["permissions"].(map[string]any) {
		got := after["permissions"].(map[string]any)[field]
		if list, ok := want.([]any); ok {
			items := got.([]any)
			if len(items) < len(list) || !reflect.DeepEqual(items[:len(list)], list) {
				t.Errorf("retained permission %s changed", field)
			}
		} else if !reflect.DeepEqual(got, want) {
			t.Errorf("unknown permission field %s changed", field)
		}
	}
	again, err := Merge(out, frag)
	if err != nil || !bytes.Equal(out, again) {
		t.Fatalf("applying twice changed the merged settings: %v", err)
	}
}

func TestMergeRenamedExecutable(t *testing.T) {
	p := loadPolicy(t, "baseline.yaml")
	o := FragmentOptions{Scope: ScopeUser, Command: "/opt/bin/cyberboar-custom", Policy: "/p.yaml", Deadline: "5s"}
	frag := BuildFragment(p, o).Settings
	first, err := Merge(nil, frag)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Merge(first, frag)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("reapplying a renamed executable duplicated hooks: %v", err)
	}
	o.Command = "/opt/bin/another-name"
	third, err := Merge(second, BuildFragment(p, o).Settings)
	if err != nil || strings.Contains(string(third), `"command": "/opt/bin/cyberboar-custom"`) {
		t.Fatalf("previous executable was retained: %v", err)
	}
	off := *p
	enabled := false
	off.Spec.Session.Briefing.Enabled = &enabled
	fourth, err := Merge(third, BuildFragment(&off, o).Settings)
	if err != nil || strings.Contains(string(fourth), `"brief"`) {
		t.Fatalf("disabled briefing retained handlers: %v", err)
	}
	// An unrelated handler with similar arguments has no CyberBoar marker
	if ours(map[string]any{"type": "command", "command": "other-tool", "args": []any{"hook"}}) {
		t.Fatal("an unrelated hook was identified as CyberBoar")
	}
}
