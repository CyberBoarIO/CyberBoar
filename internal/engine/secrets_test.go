package engine

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/internal/secrets"
	"cyberboar.dev/cyberboar/internal/secrets/secretstest"
)

func secretsPolicy(action policy.SecretsAction) *policy.Policy {
	p := emptyPolicy(policy.DenyListed)
	p.Spec.Secrets.Action = action
	return p
}

var writeConfig = Action{Tool: ToolWrite, Path: "config.yaml", Cwd: "/work/repo", Home: "/home/dev", Workspaces: []string{"/work/repo"}}

// The reason is shown to the agent and the user and logged: it must never repeat the secret
func TestSecretNotInReason(t *testing.T) {
	c := mustCompile(t, secretsPolicy(policy.SecretsDeny))
	for _, id := range secretstest.Rules() {
		secret, _ := secretstest.Fake(id)
		for _, a := range []Action{
			{Tool: ToolShell, Command: "export X='" + secret + "'", Cwd: "/work/repo", Home: "/home/dev", Workspaces: []string{"/work/repo"}},
			func() Action {
				a := writeConfig
				a.Content = "x: |\n  " + strings.ReplaceAll(secret, "\n", "\n  ") + "\n"
				return a
			}(),
		} {
			v := Evaluate(context.Background(), c, a)
			if v.Decision != Deny || !strings.HasPrefix(v.Rule, RuleSecretsPrefix) {
				t.Errorf("%s in a %s: %s by %s", id, a.Tool, v.Decision, v.Rule)
			}
			for _, part := range strings.Split(secret, "\n") {
				if len(part) > 8 && strings.Contains(v.Reason, part) {
					t.Errorf("%s: the reason repeats the secret: %s", id, v.Reason)
				}
			}
		}
	}
}

// Content too long to scan is a finding: a secret past the limit would otherwise go through
func TestSecretsTooLong(t *testing.T) {
	a := writeConfig
	a.Content = strings.Repeat("x", secrets.MaxText+1)
	for action, want := range map[policy.SecretsAction]Decision{
		policy.SecretsDeny: Deny, policy.SecretsAsk: Ask, "": Deny, policy.SecretsOff: Allow,
	} {
		v := Evaluate(context.Background(), mustCompile(t, secretsPolicy(action)), a)
		if v.Decision != want {
			t.Errorf("action %q: %s by %s, want %s", action, v.Decision, v.Rule, want)
		}
		if want != Allow && v.Rule != RuleSecretsPrefix+secrets.TooLong {
			t.Errorf("action %q: rule %s", action, v.Rule)
		}
	}
}

// A policy built without Load has no secrets action: the zero value checks, and denies
func TestSecretsZeroValueDenies(t *testing.T) {
	secret, _ := secretstest.Fake("github-pat")
	a := writeConfig
	a.Content = "token: " + secret + "\n"
	assertDeny(t, Evaluate(context.Background(), mustCompile(t, secretsPolicy("")), a), RuleSecretsPrefix+"github-pat")
}

// A scan the deadline cuts short is a deny, whether the deadline passes while
// the policy is evaluated or has already ended when the scan starts
func TestSecretsDeadline(t *testing.T) {
	secret, _ := secretstest.Fake("github-pat")
	a := writeConfig
	a.Content = "token: " + secret + "\n"
	assertDeny(t, Evaluate(expiresDuringEvaluation(), mustCompile(t, secretsPolicy(policy.SecretsDeny)), a), RuleDeadline)
	c := mustCompile(t, secretsPolicy(policy.SecretsDeny))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if v := c.evalSecrets(ctx, a); v == nil || v.Rule != RuleDeadline || v.Decision != Deny {
		t.Fatalf("scan after the deadline: %+v", v)
	}
}

func TestMultilinePrivateKeyEdits(t *testing.T) {
	key, _ := secretstest.Fake("private-key")
	key = strings.Replace(key, "\n", "\n"+strings.Repeat("\n", 20000), 1)
	header, rest, _ := strings.Cut(key, "\n")
	body, footer, _ := strings.Cut(key, "-----END ")
	encoded := base64.StdEncoding.EncodeToString([]byte(key))
	for _, tc := range []struct {
		name, old, result, added, rule string
		move                           bool
	}{
		{"add header", rest, key, header + "\n", "private-key", false},
		{"add footer", body, key, "-----END " + footer, "private-key", false},
		{"complete base64", encoded[:len(encoded)-4], encoded, encoded[len(encoded)-4:], "private-key", false},
		{"keep existing key", key, key + "\n# edited\n", "# edited\n", "", false},
		{"remove key", key, "", "", "", false},
		{"move existing key", key, key + "\n# edited\n", "# edited\n", "private-key", true},
		{"oversized result", "original", strings.Repeat("x", secrets.MaxText+1), "x", secrets.TooLong, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte(tc.old), 0o600); err != nil {
				t.Fatal(err)
			}
			a := Action{Tool: ToolWrite, Path: "/c/notes.txt", Cwd: "/c", Content: tc.added,
				Platform: PlatformWindows, Drives: map[string]string{"c": dir}, RewriteMoves: tc.move,
				Rewrite: func(old string, exists bool) ([]string, error) {
					if !exists || old != tc.old {
						t.Fatal("rewrite did not receive the existing file")
					}
					return []string{tc.result}, nil
				}}
			found, err := writeSecret(context.Background(), a, nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.rule == "" {
				if found != nil {
					t.Fatalf("ordinary edit reported %s", found.Rule)
				}
			} else if found == nil || found.Rule != tc.rule {
				t.Fatalf("finding %v, want %s", found, tc.rule)
			}
		})
	}
}
