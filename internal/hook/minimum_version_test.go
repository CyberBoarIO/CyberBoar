package hook_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/internal/adapters/claudecode"
	"cyberboar.dev/cyberboar/internal/engine"
	"cyberboar.dev/cyberboar/internal/hook"
	"cyberboar.dev/cyberboar/pkg/audit"
	"cyberboar.dev/cyberboar/pkg/brand"
	"cyberboar.dev/cyberboar/pkg/sign"
)

func TestSignedMinimumVersion(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	data := []byte("apiVersion: " + brand.APIVersion + "\nkind: Policy\nmetadata: {name: floor}\nspec: {minimumVersion: 1.4.2}\n")
	for _, tc := range []struct {
		name, version, rule string
		tampered, expired   bool
	}{
		{name: "current", version: "1.4.2", rule: hook.RuleNothingToCheck},
		{name: "newer", version: "v1.5.0+build.01", rule: hook.RuleNothingToCheck},
		{name: "older", version: "1.4.1", rule: hook.RuleVersion},
		{name: "prerelease", version: "1.4.2-rc.1", rule: hook.RuleVersion},
		{name: "development", version: "dev", rule: hook.RuleVersion},
		{name: "tampered floor", version: "1.4.1", rule: hook.RuleSignature, tampered: true},
		{name: "expired", version: "1.4.1", rule: hook.RulePolicyExpired, expired: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expiry := now.Add(time.Hour)
			if tc.expired {
				expiry = now
			}
			sig, err := sign.Sign(priv, "floor", data, sign.Header{Serial: 1, Expires: expiry})
			if err != nil {
				t.Fatal(err)
			}
			installed := data
			if tc.tampered {
				installed = []byte(strings.ReplaceAll(string(data), "1.4.2", "1.4.0"))
			}
			log := filepath.Join(t.TempDir(), "audit.jsonl")
			r := hook.Run(context.Background(), strings.NewReader("{}"), hook.Options{
				Adapter: requiredKeyAdapter{claudecode.Adapter{}}, PolicyPath: policyFile(t, installed, []byte(sig)),
				PublicKey: pub, Version: tc.version, AuditPath: log, Now: func() time.Time { return now },
			})
			if r.Verdict.Rule != tc.rule {
				t.Fatalf("want %s, got %+v", tc.rule, r.Verdict)
			}
			if tc.rule == hook.RuleNothingToCheck {
				if r.Verdict.Decision != engine.Allow {
					t.Fatal(r.Verdict)
				}
				return
			}
			assertDenied(t, r, tc.rule)
			if tc.rule == hook.RuleVersion && r.Verdict.Notice != r.Verdict.Reason {
				t.Fatal("version failure did not notify the user")
			}
			line, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			var ev audit.Event
			if err := json.Unmarshal(line, &ev); err != nil {
				t.Fatal(err)
			}
			if ev.Rule != tc.rule || ev.Decision != string(engine.Deny) || ev.PolicyName != "floor" || ev.Version != tc.version {
				t.Fatalf("wrong audit event: %+v", ev)
			}
		})
	}
}

func TestBriefMinimumVersion(t *testing.T) {
	data := []byte("apiVersion: " + brand.APIVersion + "\nkind: Policy\nmetadata: {name: floor}\nspec: {minimumVersion: 1.4.2}\n")
	path := policyFile(t, data, nil)
	for _, version := range []string{"dev", "1.4.1", "1.4.2-rc.1", "1.4.2", "1.5.0"} {
		t.Run(version, func(t *testing.T) {
			out := string(hook.Brief(hook.Options{Adapter: claudecode.Adapter{}, PolicyPath: path, Version: version}))
			blocked := version != "1.4.2" && version != "1.5.0"
			if strings.Contains(out, "every tool call is blocked") != blocked {
				t.Fatalf("briefing doesn't describe whether calls are blocked: %s", out)
			}
			if blocked && !strings.Contains(out, "1.4.2 or later") {
				t.Fatalf("briefing doesn't name the required version: %s", out)
			}
		})
	}
}
