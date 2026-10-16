package hook_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/adapters/claudecode"
	"cyberboar.dev/cyberboar/internal/adapters/codex"
	"cyberboar.dev/cyberboar/internal/adapters/copilot"
	"cyberboar.dev/cyberboar/internal/adapters/cursor"
	"cyberboar.dev/cyberboar/internal/adapters/opencode"
	"cyberboar.dev/cyberboar/internal/engine"
	"cyberboar.dev/cyberboar/internal/hook"
	"cyberboar.dev/cyberboar/internal/secrets/secretstest"
)

func adapterSecretCall(t *testing.T, adapter adapters.Adapter, input any, home, repo string) hook.Result {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	getenv := func(k string) string {
		return map[string]string{
			"HOME": home, "SHELL": "/bin/bash", "CLAUDE_PROJECT_DIR": repo,
			"COPILOT_PROJECT_DIR": repo, "CURSOR_PROJECT_DIR": repo,
		}[k]
	}
	return hook.Run(context.Background(), strings.NewReader(string(raw)), hook.Options{
		Adapter: adapter, Getenv: getenv, PolicyPath: policyFile(t, baselinePolicy(t), nil),
	})
}

func TestMCPSecretsInObjectKeys(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX adapter fixtures; native Windows rejects most of these adapters")
	}
	secret, _ := secretstest.Fake("github-pat")
	for _, tc := range []struct {
		name string
		args any
		deny bool
	}{
		{"value", map[string]any{"token": secret}, true},
		{"key", map[string]any{secret: "value"}, true},
		{"nested key", map[string]any{"metadata": map[string]any{secret: true}}, true},
		{"key inside array", map[string]any{"items": []any{map[string]any{secret: nil}}}, true},
		{"harmless", map[string]any{"metadata": map[string]any{"label": "value"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, err := json.Marshal(tc.args)
			if err != nil {
				t.Fatal(err)
			}
			for _, ac := range []struct {
				adapter adapters.Adapter
				input   any
			}{
				{claudecode.Adapter{}, map[string]any{"hook_event_name": "PreToolUse", "tool_name": "mcp__github__create_issue", "mcp_server": map[string]any{"name": "github"}, "tool_input": tc.args}},
				{codex.Adapter{}, map[string]any{"hook_event_name": "PreToolUse", "tool_name": "mcp__github__create_issue", "tool_input": tc.args}},
				{copilot.Adapter{}, map[string]any{"toolName": "github-create_issue", "toolArgs": tc.args}},
				{cursor.Adapter{}, map[string]any{"hook_event_name": "beforeMCPExecution", "tool_name": "MCP:create_issue", "mcp_server_name": "github", "tool_input": string(args)}},
				{opencode.Adapter{}, map[string]any{"tool": "github_create_issue", "sessionID": "s1", "directory": "/work/repo", "worktree": "/work/repo", "shell": "/bin/bash", "mcpServers": []string{"github"}, "args": tc.args}},
			} {
				t.Run(ac.adapter.Name(), func(t *testing.T) {
					r := adapterSecretCall(t, ac.adapter, ac.input, "/home/dev", "/work/repo")
					if tc.deny {
						if r.Verdict.Decision != engine.Deny || r.Verdict.Rule != "secrets.github-pat" {
							t.Fatalf("MCP call: %s by %s; want deny by secrets.github-pat", r.Verdict.Decision, r.Verdict.Rule)
						}
					} else if r.Verdict.Decision != engine.Allow {
						t.Fatalf("harmless MCP call: %s by %s", r.Verdict.Decision, r.Verdict.Rule)
					}
				})
			}
		})
	}
}

func TestOpencodeResourceSecrets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("opencode adapter fixtures use POSIX paths")
	}
	secret, _ := secretstest.Fake("github-pat")
	encoded, _ := secretstest.Hide(secret, "punct")
	for _, tc := range []struct {
		name, uri string
		deny      bool
	}{
		{"credential in URI", "https://example.com/resource?token=" + secret, true},
		{"encoded credential in URI", "https://example.com/resource?token=" + encoded, true},
		{"public resource", "docs://public", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := map[string]any{
				"tool": "read_mcp_resource", "sessionID": "s1",
				"directory": "/work/repo", "worktree": "/work/repo", "shell": "/bin/bash",
				"mcpServers": []string{"github"}, "args": map[string]any{"server": "github", "uri": tc.uri},
			}
			r := adapterSecretCall(t, opencode.Adapter{}, in, "/home/dev", "/work/repo")
			if tc.deny {
				assertDenied(t, r, "secrets.github-pat")
			} else if r.Verdict.Decision != engine.Allow {
				t.Fatalf("public resource: %s by %s", r.Verdict.Decision, r.Verdict.Rule)
			}
		})
	}
}

func TestOversizedReplacementEdits(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Claude adapter fixtures use POSIX paths")
	}
	for _, tc := range []struct {
		name, old, find, with string
	}{
		{"exact", strings.Repeat("a", 64<<10), "a", strings.Repeat("b", 128)},
		{"loose", strings.Repeat("a ", 32<<10), "a\t", strings.Repeat("b", 256)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			repo := filepath.Join(home, "repo")
			if err := os.Mkdir(repo, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(repo, "notes.txt")
			if err := os.WriteFile(path, []byte(tc.old), 0o600); err != nil {
				t.Fatal(err)
			}
			in := map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Edit", "cwd": repo,
				"tool_input": map[string]any{"file_path": path, "old_string": tc.find, "new_string": tc.with, "replace_all": true}}
			assertDenied(t, adapterSecretCall(t, claudecode.Adapter{}, in, home, repo), "secrets.too-long")
		})
	}
}

func TestPatchMoveSecrets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX adapter fixtures; patch adapters are unsupported on native Windows")
	}
	secret, _ := secretstest.Fake("github-pat")
	// Keep the credential well before the lines changed by the patch
	old := "token = " + secret + "\n" + strings.Repeat("# unchanged\n", 2048) + "original\n"
	for _, tc := range []struct {
		name, old, move, hunk string
		deny                  bool
	}{
		{"preserved secret", old, "*** Move to: dest.txt\n", "@@\n-original\n+updated\n", true},
		{"trimmed source path", old, "*** Move to: dest.txt\n", "@@\n-original\n+updated\n", true},
		{"ordinary edit", old, "", "@@\n-original\n+updated\n", false},
		{"clean move", "original\n", "*** Move to: dest.txt\n", "@@\n-original\n+updated\n", false},
		{"removed secret", "token = " + secret + "\n", "*** Move to: dest.txt\n", "@@\n-token = " + secret + "\n+token = ${GITHUB_TOKEN}\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "home")
			repo := filepath.Join(home, "repo")
			if err := os.MkdirAll(repo, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(repo, "source.txt"), []byte(tc.old), 0o600); err != nil {
				t.Fatal(err)
			}
			source := "source.txt"
			if tc.name == "trimmed source path" {
				source = " " + source
			}
			patch := "*** Begin Patch\n*** Update File: " + source + "\n" + tc.move + tc.hunk + "*** End Patch\n"
			for _, ac := range []struct {
				adapter adapters.Adapter
				input   any
			}{
				{codex.Adapter{}, map[string]any{"hook_event_name": "PreToolUse", "tool_name": "apply_patch", "cwd": repo, "tool_input": map[string]any{"command": patch}}},
				{copilot.Adapter{}, map[string]any{"toolName": "apply_patch", "cwd": repo, "toolArgs": patch}},
				{opencode.Adapter{}, map[string]any{"tool": "apply_patch", "sessionID": "s1", "directory": repo, "worktree": repo, "shell": "/bin/bash", "mcpServers": []string{}, "args": map[string]any{"patchText": patch}}},
			} {
				t.Run(ac.adapter.Name(), func(t *testing.T) {
					r := adapterSecretCall(t, ac.adapter, ac.input, home, repo)
					if tc.deny {
						assertDenied(t, r, "secrets.github-pat")
					} else if r.Verdict.Decision != engine.Allow {
						t.Fatalf("patch: %s by %s (%s)", r.Verdict.Decision, r.Verdict.Rule, r.Verdict.Reason)
					}
				})
			}
		})
	}
}

func TestMultilinePrivateKeyCalls(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX adapter fixtures")
	}
	key, _ := secretstest.Fake("private-key")
	key = strings.Replace(key, "\n", "\n"+strings.Repeat("\n", 20000), 1)
	header, rest, _ := strings.Cut(key, "\n")
	body, footer, _ := strings.Cut(key, "-----END ")
	for _, tc := range []struct {
		name, tool, old string
		args            map[string]any
	}{
		{"MCP", "mcp__github__create_issue", "", map[string]any{"text": key}},
		{"encoded MCP", "mcp__github__create_issue", "", map[string]any{"text": base64.StdEncoding.EncodeToString([]byte(key))}},
		{"write", "Write", "", map[string]any{"content": key}},
		{"edit header", "Edit", "pending\n" + rest, map[string]any{"old_string": "pending\n", "new_string": header + "\n"}},
		{"edit footer", "Edit", body + "pending", map[string]any{"old_string": "pending", "new_string": "-----END " + footer}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			repo := filepath.Join(home, "repo")
			if err := os.Mkdir(repo, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(repo, "notes.txt")
			if err := os.WriteFile(path, []byte(tc.old), 0o600); err != nil {
				t.Fatal(err)
			}
			in := map[string]any{"hook_event_name": "PreToolUse", "tool_name": tc.tool, "cwd": repo, "tool_input": tc.args}
			if strings.HasPrefix(tc.tool, "mcp__") {
				in["mcp_server"] = map[string]any{"name": "github"}
			} else {
				tc.args["file_path"] = path
			}
			assertDenied(t, adapterSecretCall(t, claudecode.Adapter{}, in, home, repo), "secrets.private-key")
		})
	}
}
