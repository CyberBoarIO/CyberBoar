package codex

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/engine"
)

// Codex runs the tool when a hook answers "ask", so nothing but deny or
// silence may ever come out.
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
		// Exit 0: under PowerShell, a hook's exit 2 reaches Codex as 1, a failed hook
		if out.Exit != 0 || got.HSO.Event != "PreToolUse" || got.HSO.Decision != "deny" || !strings.HasPrefix(got.HSO.Reason, "cb: because") ||
			out.Stderr != "" {
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
// 1.4 s in is found, one written 1.6 s in is refused, and no test sleeps.
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
				if ae, ok := errors.AsType[*adapters.Error](err); !ok || ae.Rule != RuleCallNotFound {
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

// Only the end of a large transcript is read; a call there is still found.
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
// than Codex uses.
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
		if ae, ok := errors.AsType[*adapters.Error](err); !ok || ae.Rule != RuleCallNotFound {
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

// Codex reports MCP names in its own form, so every split says so.
func TestMCPCallsHaveCodexNames(t *testing.T) {
	in := &Input{HookEventName: "PreToolUse", Cwd: "/work", ToolName: "mcp__fs_srv__write_file", ToolInput: json.RawMessage(`{}`)}
	actions, err := Actions(in, Env{Home: "/home/dev", Shell: "/bin/bash"})
	if err != nil || len(actions) == 0 {
		t.Fatalf("%d actions, %v", len(actions), err)
	}
	for _, a := range actions {
		if a.Tool != engine.ToolMCP || a.MCP.Names != engine.NamesCodex {
			t.Errorf("action %+v", a.MCP)
		}
	}
}

// On native Windows Codex runs commands in PowerShell: they are analysed as
// PowerShell with Windows paths, a shell other than PowerShell is refused,
// and the user's PowerShell folders, Codex's settings and the managed
// directory are guarded.
func TestWindows(t *testing.T) {
	c, err := engine.Compile(loadPolicy(t, "baseline.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	transcript := filepath.Join(t.TempDir(), "rollout.jsonl")
	run := func(t *testing.T, args map[string]any, documents string) (*adapters.Call, engine.Verdict) {
		t.Helper()
		js, _ := json.Marshal(args)
		line, _ := json.Marshal(map[string]any{"type": "response_item", "payload": map[string]any{
			"type": "function_call", "name": "exec_command", "call_id": "c1", "arguments": string(js)}})
		if err := os.WriteFile(transcript, append(line, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		input, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "s", "cwd": `C:\work\repo`,
			"transcript_path": transcript, "tool_use_id": "c1", "tool_name": "Bash", "tool_input": map[string]any{"command": args["cmd"]}})
		getenv := func(k string) string {
			return map[string]string{"USERPROFILE": `C:\Users\dev`, "HOME": "/home/ignored", "SHELL": "/bin/bash"}[k]
		}
		call, err := parse(input, getenv, "windows", func() string { return documents })
		if err != nil {
			t.Fatal(err)
		}
		if call.Err != nil {
			return call, engine.Verdict{}
		}
		var vs []engine.Verdict
		for _, a := range call.Actions {
			// The transcript is this machine's file, not a Windows path, as it
			// would be on Windows; the engine refuses it in a Windows action
			a.Guarded = slices.DeleteFunc(slices.Clone(a.Guarded), func(p string) bool { return p == transcript })
			vs = append(vs, engine.Evaluate(context.Background(), c, a))
		}
		v, _ := engine.Strictest(vs)
		return call, v
	}
	for _, tc := range []struct {
		name      string
		args      map[string]any
		documents string
		decision  engine.Decision
		rule      string
	}{
		{"secret", map[string]any{"cmd": "Get-Content .env"}, "", engine.Deny, "files.deny[0]"},
		{"harmless", map[string]any{"cmd": "Get-ChildItem; git status"}, "", engine.Allow, ""},
		{"pwsh by path", map[string]any{"cmd": "Get-ChildItem", "shell": `C:\Program Files\PowerShell\7\pwsh.exe`}, "", engine.Allow, ""},
		{"login shell", map[string]any{"cmd": "Get-ChildItem", "login": true}, "", engine.Allow, ""},
		{"workdir", map[string]any{"cmd": "Get-Content ..\\.env", "workdir": "src"}, "", engine.Deny, "files.deny[0]"},
		{"profile", map[string]any{"cmd": `Set-Content C:\Users\dev\Documents\PowerShell\profile.ps1 x`}, "", engine.Deny, engine.RuleGuarded},
		{"redirected module", map[string]any{"cmd": `Set-Content D:\OneDrive\Documents\WindowsPowerShell\Modules\m\m.psm1 x`}, `D:\OneDrive\Documents`, engine.Deny, engine.RuleGuarded},
		{"hooks", map[string]any{"cmd": `Set-Content C:\Users\dev\.codex\hooks.json '{}'`}, "", engine.Deny, engine.RuleGuarded},
		{"managed", map[string]any{"cmd": `Set-Content C:\ProgramData\OpenAI\Codex\requirements.toml x`}, "", engine.Deny, engine.RuleGuarded},
		{"startup file", map[string]any{"cmd": `Add-Content C:\Users\dev\.bashrc x`}, "", engine.Deny, engine.RuleGuarded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			call, v := run(t, tc.args, tc.documents)
			if call.Err != nil {
				t.Fatalf("refused: %v", call.Err)
			}
			if a := call.Actions[0]; a.Shell != engine.ShellPowerShell || a.Platform != engine.PlatformWindows || a.Home != `C:\Users\dev` {
				t.Errorf("action %+v", a)
			}
			if v.Decision != tc.decision || (tc.rule != "" && v.Rule != tc.rule) {
				t.Errorf("%s by %s (%s); want %s %s", v.Decision, v.Rule, v.Reason, tc.decision, tc.rule)
			}
		})
	}
	// A refused command stays in the actions for the audit log
	for _, tc := range []struct {
		name  string
		args  map[string]any
		shell string
	}{
		{"cmd", map[string]any{"cmd": "dir", "shell": `C:\Windows\System32\cmd.exe`}, ""},
		{"git bash", map[string]any{"cmd": "ls", "shell": `C:\Program Files\Git\bin\bash.exe`}, ""},
		{"drive-relative workdir", map[string]any{"cmd": "dir", "workdir": `D:x`}, engine.ShellPowerShell},
		{"rooted workdir", map[string]any{"cmd": "dir", "workdir": `\x`}, engine.ShellPowerShell},
		{"tty", map[string]any{"cmd": "dir", "tty": true}, engine.ShellPowerShell},
	} {
		t.Run(tc.name, func(t *testing.T) {
			call, _ := run(t, tc.args, "")
			if call.Err == nil {
				t.Fatalf("accepted: %+v", call.Actions)
			}
			if len(call.Actions) != 1 || call.Actions[0].Command != tc.args["cmd"] || call.Actions[0].Shell != tc.shell {
				t.Errorf("actions %+v", call.Actions)
			}
		})
	}
}

func TestIsPowerShell(t *testing.T) {
	for shell, want := range map[string]bool{"pwsh": true, "powershell": true, `C:\Program Files\PowerShell\7\pwsh.exe`: true,
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`: true, "/usr/bin/pwsh": true,
		"cmd": false, "PWSH.EXE": false, `C:\x\pwsh-preview.exe`: false, "bash": false} {
		if got := isPowerShell(shell); got != want {
			t.Errorf("isPowerShell(%q) = %v", shell, got)
		}
	}
}
