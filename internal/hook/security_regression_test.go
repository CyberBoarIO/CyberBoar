package hook_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/adapters/claudecode"
	"cyberboar.dev/cyberboar/internal/adapters/codex"
	"cyberboar.dev/cyberboar/internal/adapters/copilot"
	"cyberboar.dev/cyberboar/internal/adapters/cursor"
	"cyberboar.dev/cyberboar/internal/adapters/opencode"
	"cyberboar.dev/cyberboar/internal/engine"
	"cyberboar.dev/cyberboar/internal/hook"
	"cyberboar.dev/cyberboar/internal/secrets/secretstest"
	"cyberboar.dev/cyberboar/pkg/sign"
)

type decisionAdapter struct {
	claudecode.Adapter
	action engine.Action
}

func TestRequiredKeyErrorsDenyEveryAgent(t *testing.T) {
	root := t.TempDir()
	key := filepath.Join(root, "key.pem")
	if err := os.WriteFile(key, []byte(strings.Repeat("x", 4097)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, adapter := range []adapters.Adapter{claudecode.Adapter{}, codex.Adapter{}, copilot.Adapter{}, cursor.Adapter{}, opencode.Adapter{}} {
		t.Run(adapter.Name(), func(t *testing.T) {
			for _, path := range []string{key, root, filepath.Join(root, "missing")} {
				r := hook.Run(context.Background(), strings.NewReader(bashLS), hook.Options{
					Adapter: requiredKeyAdapter{adapter}, PublicKeyPath: path,
					PolicyPath: policyFile(t, baselinePolicy(t), nil),
				})
				if r.Verdict.Decision != engine.Deny {
					t.Fatalf("%s: allowed with unusable key: %+v", path, r)
				}
				if r.Verdict.Rule != hook.RuleHookSetup {
					t.Fatalf("%s: %s", path, r.Verdict.Rule)
				}
			}
		})
	}
}

type requiredKeyAdapter struct{ adapters.Adapter }

func (a requiredKeyAdapter) Parse([]byte, func(string) string) (*adapters.Call, error) {
	return &adapters.Call{}, nil
}

func TestOversizedPolicyDenied(t *testing.T) {
	data := append(baselinePolicy(t), []byte("# "+strings.Repeat("x", 1<<20))...)
	r := hook.Run(context.Background(), strings.NewReader(bashLS), hook.Options{
		Adapter: claudecode.Adapter{}, Getenv: env, PolicyPath: policyFile(t, data, nil),
	})
	assertDenied(t, r, engine.RuleNoPolicy)
}

func (a decisionAdapter) Parse([]byte, func(string) string) (*adapters.Call, error) {
	return &adapters.Call{Actions: []engine.Action{a.action}}, nil
}

// TestPolicyExpiresDuringEvaluation advances the injected clock while an
// otherwise permitted edit is evaluated, after the signature was checked
func TestPolicyExpiresDuringEvaluation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	expiry := now.Add(time.Second)
	data := baselinePolicy(t)
	sig, err := sign.Sign(priv, "baseline", data, sign.Header{Serial: 1, Expires: expiry})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	a := engine.Action{Tool: engine.ToolWrite, Path: "notes.txt", Cwd: root, Home: t.TempDir(), Workspaces: []string{root}}
	a.Rewrite = func(string, bool) ([]string, error) {
		now = expiry
		return []string{"harmless text"}, nil
	}
	r := hook.Run(context.Background(), strings.NewReader("{}"), hook.Options{
		Adapter: decisionAdapter{action: a}, PolicyPath: policyFile(t, data, []byte(sig)),
		PublicKey: pub, Now: func() time.Time { return now },
	})
	if now != expiry {
		t.Fatal("edit did not advance the clock")
	}
	assertDenied(t, r, hook.RulePolicyExpired)
}

func TestPolicyExpiresDuringAudit(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	expiry := now.Add(time.Second)
	data := baselinePolicy(t)
	sig, err := sign.Sign(priv, "baseline", data, sign.Header{Serial: 1, Expires: expiry})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	log := filepath.Join(t.TempDir(), "audit.jsonl")
	action := engine.Action{Tool: engine.ToolRead, Path: "notes.txt", Cwd: root, Home: t.TempDir(), Workspaces: []string{root}}
	r := hook.Run(context.Background(), strings.NewReader("{}"), hook.Options{
		Adapter: decisionAdapter{action: action}, PolicyPath: policyFile(t, data, []byte(sig)), PublicKey: pub, AuditPath: log,
		Now: func() time.Time {
			if info, err := os.Stat(log); err == nil && info.Size() > 0 {
				return expiry
			}
			return now
		},
	})
	assertDenied(t, r, hook.RulePolicyExpired)
}

func TestAuditModePreservesSecretEnforcement(t *testing.T) {
	root := t.TempDir()
	credential := secretstest.Expand("{{fake:github-pat}}")
	action := engine.Action{Tool: engine.ToolShell, Command: "echo " + credential, Cwd: root, Home: t.TempDir(), Workspaces: []string{root}}
	for _, log := range []string{"", filepath.Join(t.TempDir(), "audit.jsonl")} {
		r := hook.Run(context.Background(), strings.NewReader("{}"), hook.Options{
			Adapter: decisionAdapter{action: action}, PolicyPath: policyFile(t, baselinePolicy(t), nil), AuditPath: log,
		})
		assertDenied(t, r, "secrets.github-pat")
		if log != "" {
			data, err := os.ReadFile(log)
			if err != nil || strings.Contains(string(data), credential) {
				t.Fatalf("audit leaked a secret or failed: %v", err)
			}
		}
	}
}

func TestPolicyLockIsGuarded(t *testing.T) {
	path := policyFile(t, baselinePolicy(t), nil)
	root := t.TempDir()
	action := engine.Action{Tool: engine.ToolWrite, Path: path + ".lock", Cwd: root, Home: t.TempDir(), Workspaces: []string{root}}
	r := hook.Run(context.Background(), strings.NewReader("{}"), hook.Options{Adapter: decisionAdapter{action: action}, PolicyPath: path})
	assertDenied(t, r, engine.RuleGuarded)
}
