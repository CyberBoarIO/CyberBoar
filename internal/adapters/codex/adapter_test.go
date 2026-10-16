package codex

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/engine"
)

// Codex runs the tool when a hook answers "ask", so nothing but deny or
// silence may ever come out
func TestRespondNeverAsksOrAllows(t *testing.T) {
	for _, d := range []engine.Decision{engine.Ask, engine.Deny} {
		out := Adapter{}.Respond(engine.Verdict{Decision: d, Rule: "r", Reason: "because"}, "cb: ")
		var got struct {
			HSO struct {
				Event    string `json:"hookEventName"`
				Decision string `json:"permissionDecision"`
				Reason   string `json:"permissionDecisionReason"`
			} `json:"hookSpecificOutput"`
		}
		if err := json.Unmarshal(out.Stdout, &got); err != nil {
			t.Fatal(err)
		}
		if out.Exit != 2 || got.HSO.Event != "PreToolUse" || got.HSO.Decision != "deny" || !strings.HasPrefix(got.HSO.Reason, "cb: because") ||
			!strings.Contains(out.Stderr, "because") {
			t.Errorf("%s: %+v %+v", d, out, got)
		}
		if d == engine.Ask && !strings.Contains(got.HSO.Reason, "can't ask") {
			t.Errorf("an ask turned deny must say why: %q", got.HSO.Reason)
		}
	}
	if out := (Adapter{}).Respond(engine.Verdict{Decision: engine.Allow}, "cb: "); out.Exit != 0 || len(out.Stdout) != 0 || out.Stderr != "" {
		t.Errorf("allow must produce no output: %+v", out)
	}
}

// Codex may still be writing the call when the hook runs, so the adapter
// waits for it, 1.5 s at most. The bubble's clock is fake: a call written
// 1.4 s in is found, one written 1.6 s in is refused, and no test sleeps
func TestTranscriptCallArrivesLate(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write time.Duration
		found bool
	}{
		{"within the wait", 1400 * time.Millisecond, true},
		{"after the wait", 1600 * time.Millisecond, false},
	} {
		synctest.Test(t, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rollout.jsonl")
			os.WriteFile(path, []byte(`{"type":"session_meta","payload":{}}`+"\n"), 0o600)
			written := make(chan struct{})
			go func() {
				defer close(written)
				time.Sleep(tc.write)
				f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
				f.WriteString(`{"type":"response_item","payload":{"type":"function_call","name":"exec_command","arguments":"{\"cmd\":\"ls\",\"workdir\":\"src\"}","call_id":"c1"}}` + "\n")
				f.Close()
			}()
			in := &Input{ToolUseID: "c1", TranscriptPath: &path}
			call, err := lookupExecCall(in, "ls")
			<-written
			if !tc.found {
				var ae *adapters.Error
				if !errors.As(err, &ae) || ae.Rule != RuleCallNotFound {
					t.Errorf("%s: call %+v, err %v; want %s", tc.name, call, err, RuleCallNotFound)
				}
				return
			}
			if err != nil || call.Cmd != "ls" || call.Workdir == nil || *call.Workdir != "src" {
				t.Fatalf("%s: call %+v, err %v", tc.name, call, err)
			}
		})
	}
}

// Only the end of a large transcript is read; a call there is still found
func TestTranscriptTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollout.jsonl")
	big := strings.Repeat(`{"type":"event_msg","payload":{"text":"`+strings.Repeat("x", 1000)+`"}}`+"\n", transcriptTail/1000+10)
	os.WriteFile(path, []byte(big+`{"type":"response_item","payload":{"type":"function_call","name":"exec_command","arguments":"{\"cmd\":\"ls\"}","call_id":"c9"}}`+"\n"), 0o600)
	if call, err := lookupExecCall(&Input{ToolUseID: "c9", TranscriptPath: &path}, "ls"); err != nil || call.Cmd != "ls" {
		t.Fatalf("call %+v, err %v", call, err)
	}
}

// Codex reads the arguments with exact key names and ignores other keys;
// encoding/json also takes a key that differs in case, and the last of two.
// Any such key is refused, so the hook can't read another workdir or shell
// than Codex uses
func TestTranscriptArgumentKeys(t *testing.T) {
	for name, args := range map[string]string{
		"mis-cased":         `{"cmd":"ls","workdir":"/root","Workdir":null}`,
		"equal when folded": `{"cmd":"ls","workdir":"/root","worKdir":null}`,
		"long s":            `{"cmd":"ls","shell":"/usr/bin/fish","ſhell":null}`,
		"twice":             `{"cmd":"ls","workdir":"/root","workdir":null}`,
		"not an object":     `["ls"]`,
	} {
		path := filepath.Join(t.TempDir(), "rollout.jsonl")
		line, _ := json.Marshal(map[string]any{"type": "response_item", "payload": map[string]any{
			"type": "function_call", "name": "exec_command", "arguments": args, "call_id": "c1"}})
		os.WriteFile(path, append(line, '\n'), 0o600)
		call, err := lookupExecCall(&Input{ToolUseID: "c1", TranscriptPath: &path}, "ls")
		var ae *adapters.Error
		if !errors.As(err, &ae) || ae.Rule != RuleCallNotFound {
			t.Errorf("%s: call %+v, err %v; want %s", name, call, err, RuleCallNotFound)
		}
	}
	path := filepath.Join(t.TempDir(), "rollout.jsonl")
	os.WriteFile(path, []byte(`{"type":"response_item","payload":{"type":"function_call","name":"exec_command","arguments":"{\"cmd\":\"ls\",\"max_output_tokens\":10,\"Other\":1}","call_id":"c2"}}`+"\n"), 0o600)
	if _, err := lookupExecCall(&Input{ToolUseID: "c2", TranscriptPath: &path}, "ls"); err != nil {
		t.Errorf("keys that name no field of the call: %v", err)
	}
}

func TestReadLineSkipsOverlongLines(t *testing.T) {
	long := strings.Repeat("x", maxLine) + strings.Repeat("y", 100<<10)
	r := bufio.NewReader(strings.NewReader(long + "\nnext\n"))
	for _, want := range []string{"", "next"} {
		line, err := readLine(r)
		if err != nil || string(line) != want {
			t.Fatalf("readLine = %.20q…, %v; want %q", line, err, want)
		}
	}
}

// Codex reports MCP names in its own form, so every split says so
func TestMCPCallsHaveCodexNames(t *testing.T) {
	in := &Input{HookEventName: "PreToolUse", Cwd: "/work", ToolName: "mcp__fs_srv__write_file", ToolInput: json.RawMessage(`{}`)}
	actions, err := Actions(in, "/home/dev", "/bin/bash", false)
	if err != nil || len(actions) == 0 {
		t.Fatalf("%d actions, %v", len(actions), err)
	}
	for _, a := range actions {
		if a.Tool != engine.ToolMCP || a.MCP.Names != engine.NamesCodex {
			t.Errorf("action %+v", a.MCP)
		}
	}
}
