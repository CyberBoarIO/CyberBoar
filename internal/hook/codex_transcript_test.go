package hook_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/adapters/codex"
	"cyberboar.dev/cyberboar/internal/engine"
	"cyberboar.dev/cyberboar/internal/hook"
)

func TestCodexTranscriptIntegrity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Codex adapter fixtures use POSIX paths")
	}
	for _, layout := range []string{"default", "custom home", "relocated transcript"} {
		t.Run(layout, func(t *testing.T) {
			home := t.TempDir()
			repo := filepath.Join(home, "repo")
			codexHome := filepath.Join(home, ".codex")
			env := map[string]string{"HOME": home, "SHELL": "/bin/bash"}
			if layout == "custom home" {
				codexHome = filepath.Join(home, "custom-codex")
				env["CODEX_HOME"] = codexHome
			}
			transcript := filepath.Join(codexHome, "sessions", "current.jsonl")
			if layout == "relocated transcript" {
				transcript = filepath.Join(home, "relocated", "current.jsonl")
			}
			for _, dir := range []string{repo, filepath.Join(home, ".ssh"), filepath.Dir(transcript)} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			read := "cat " + adapters.ShellQuote(transcript)
			write := "printf x >> " + adapters.ShellQuote(transcript)
			literal := func(s string) string {
				b, err := json.Marshal(s)
				if err != nil {
					t.Fatal(err)
				}
				return string(b)
			}
			script := `await tools.exec_command({cmd:"cat id_rsa",workdir:` + literal(filepath.Join(home, ".ssh")) + `});` +
				`await tools.exec_command({cmd:` + literal(read) + `});` +
				`await tools.exec_command({cmd:` + literal(write) + `});` +
				`await tools.exec_command({cmd:"date"});`
			line, err := json.Marshal(map[string]any{"type": "response_item", "payload": map[string]any{
				"type": "custom_tool_call", "call_id": "script1", "name": "exec", "input": script,
			}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(transcript, append(line, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			policy := policyFile(t, baselinePolicy(t), nil)
			call := func(tool, command string) hook.Result {
				t.Helper()
				raw, err := json.Marshal(map[string]any{
					"hook_event_name": "PreToolUse", "session_id": "review", "cwd": repo,
					"transcript_path": transcript, "tool_use_id": "exec-review", "tool_name": tool,
					"tool_input": map[string]any{"command": command},
				})
				if err != nil {
					t.Fatal(err)
				}
				return hook.Run(context.Background(), bytes.NewReader(raw), hook.Options{
					Adapter: codex.Adapter{}, PolicyPath: policy, Getenv: func(k string) string { return env[k] },
				})
			}
			// The adapter can still read the transcript and recover command arguments
			if r := call("Bash", "date"); r.Verdict.Decision != engine.Allow {
				t.Fatalf("ordinary command: %s by %s", r.Verdict.Decision, r.Verdict.Rule)
			}
			assertDenied(t, call("Bash", "cat id_rsa"), "files.deny[2]")
			t.Run("shell read", func(t *testing.T) {
				assertDenied(t, call("Bash", read), "builtin.guarded")
			})
			t.Run("shell write", func(t *testing.T) {
				assertDenied(t, call("Bash", write), "builtin.guarded")
			})

			forged := strings.ReplaceAll(string(line), filepath.Join(home, ".ssh"), repo)
			for name, body := range map[string]string{
				"rewrite active": "*** Update File: " + transcript + "\n@@\n-" + string(line) + "\n+" + forged + "\n",
				"delete active":  "*** Delete File: " + transcript + "\n",
				"move active":    "*** Update File: " + transcript + "\n*** Move to: " + repo + "/moved.jsonl\n@@\n-" + string(line) + "\n+" + forged + "\n",
				"replace active": "*** Update File: " + repo + "/source.jsonl\n*** Move to: " + transcript + "\n@@\n-old\n+new\n",
				"other session":  "*** Add File: " + filepath.Join(codexHome, "sessions", "other.jsonl") + "\n+{}\n",
				"archived":       "*** Add File: " + filepath.Join(codexHome, "archived_sessions", "other.jsonl") + "\n+{}\n",
				"unrelated file": "*** Add File: " + repo + "/notes.txt\n+hello\n",
			} {
				t.Run(name, func(t *testing.T) {
					r := call("apply_patch", "*** Begin Patch\n"+body+"*** End Patch\n")
					if name == "unrelated file" {
						if r.Verdict.Decision != engine.Allow {
							t.Fatalf("ordinary patch: %s by %s", r.Verdict.Decision, r.Verdict.Rule)
						}
					} else {
						assertDenied(t, r, "builtin.guarded")
					}
				})
			}
		})
	}
}
