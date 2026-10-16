package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestProjectPolicyComponents(t *testing.T) {
	dir := t.TempDir()
	for _, rel := range []string{"policy.yaml", "..policy.yaml", filepath.Join("..policies", "policy.yaml")} {
		got, err := projectPolicy(dir, filepath.Join(dir, rel))
		if err != nil || got != filepath.ToSlash(rel) {
			t.Errorf("in-project policy %q: path %q, error %v", rel, got, err)
		}
	}
	for _, policy := range []string{filepath.Dir(dir), filepath.Join(filepath.Dir(dir), "outside.yaml")} {
		if _, err := projectPolicy(dir, policy); err == nil {
			t.Errorf("accepted policy outside the project: %s", policy)
		}
	}
	if runtime.GOOS == "windows" {
		if _, err := projectPolicy(`C:\repo`, `D:\policy.yaml`); err == nil {
			t.Error("accepted policy on another volume")
		}
	}
}

func TestApplyProjectPolicyDotPrefix(t *testing.T) {
	policy, err := os.ReadFile(baseline)
	if err != nil {
		t.Fatal(err)
	}
	for _, agent := range []string{"claude-code", "codex", "copilot-cli", "cursor", "opencode"} {
		t.Run(agent, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "..policies", "policy.yaml")
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, policy, 0o600); err != nil {
				t.Fatal(err)
			}
			var out, errb bytes.Buffer
			h := host{goos: "linux", now: time.Now, getenv: func(key string) string { return "" }}
			code := h.run([]string{"apply", "-agent", agent, "-policy", path, "-scope", "project", "-dir", dir},
				nil, &out, &errb)
			if code != 0 || !strings.Contains(out.String(), "..policies/policy.yaml") {
				t.Fatalf("in-project dot-prefixed policy: exit %d, stdout %s, stderr %s", code, &out, &errb)
			}
		})
	}
}

func TestApplyRefusesMalformedSettingsWithoutWriting(t *testing.T) {
	for _, agent := range []struct{ name, directory, file string }{
		{"claude-code", ".claude", "settings.json"},
		{"codex", ".codex", "hooks.json"},
		{"cursor", ".cursor", "hooks.json"},
	} {
		for _, input := range []string{"null", "[]", "{} {}", "{} garbage", "{} {"} {
			t.Run(agent.name+"/"+input, func(t *testing.T) {
				home := t.TempDir()
				target := filepath.Join(home, agent.directory, agent.file)
				if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, []byte(input), 0o600); err != nil {
					t.Fatal(err)
				}
				h := host{goos: "linux", now: time.Now, getenv: func(key string) string {
					if key == "HOME" {
						return home
					}
					return ""
				}}
				var out, errb bytes.Buffer
				code := h.run([]string{"apply", "-agent", agent.name, "-policy", baseline,
					"-scope", "user", "-command", "cyberboar", "-write"}, nil, &out, &errb)
				if code != 1 || !strings.Contains(errb.String(), target) {
					t.Fatalf("invalid settings: exit %d, stderr %s", code, &errb)
				}
				after, err := os.ReadFile(target)
				if err != nil || string(after) != input {
					t.Fatalf("refused apply changed settings: %q, %v", after, err)
				}
				if _, err := os.Stat(target + ".bak"); !os.IsNotExist(err) {
					t.Fatalf("refused apply created a backup: %v", err)
				}
			})
		}
	}
}

func TestAbsoluteApplyPaths(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	got, err := absoluteApplyPaths(applyArgs{policy: "policy.yaml", dir: ".", pubkey: "policy.pub", audit: "audit.jsonl", state: "state"})
	if err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"policy": got.policy, "dir": got.dir, "pubkey": got.pubkey, "audit": got.audit, "state": got.state} {
		if !filepath.IsAbs(path) || filepath.Dir(path) != cwd && path != cwd {
			t.Errorf("%s was not resolved against the working directory: %q", name, path)
		}
	}
	got, err = absoluteApplyPaths(applyArgs{policy: "policy.yaml", dir: "."})
	if err != nil || got.pubkey != "" || got.audit != "" || got.state != "" {
		t.Fatalf("empty optional paths changed: %+v, %v", got, err)
	}
}

func TestApplyPathFailureDoesNotWrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows keeps the current directory open")
	}
	root := t.TempDir()
	cwd := filepath.Join(root, "removed")
	if err := os.Mkdir(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	if err := os.Remove(cwd); err != nil {
		t.Fatal(err)
	}
	// A removed working directory may still resolve on macOS. This test
	// requires filepath.Abs to fail before checking that apply writes nothing
	if _, err := filepath.Abs("policy.yaml"); err == nil {
		t.Skip("relative paths still resolve after removing the working directory")
	}
	for _, agent := range []string{"claude-code", "codex", "copilot-cli", "cursor", "opencode"} {
		var out, errb bytes.Buffer
		h := host{goos: "linux", now: time.Now, getenv: func(key string) string { return "" }}
		code := h.run([]string{"apply", "-agent", agent, "-policy", "policy.yaml", "-dir", root,
			"-scope", "project", "-command", "cyberboar", "-write"}, nil, &out, &errb)
		if code != 1 || !strings.Contains(errb.String(), "-policy: can't resolve an absolute path") || out.Len() != 0 {
			t.Errorf("%s: exit %d, stdout %s, stderr %s", agent, code, &out, &errb)
		}
	}
	for _, flag := range []string{"dir", "pubkey", "audit", "state"} {
		var out, errb bytes.Buffer
		h := host{goos: "linux", now: time.Now, getenv: func(key string) string { return "" }}
		args := []string{"apply", "-policy", filepath.Join(root, "policy.yaml"), "-dir", root,
			"-command", "cyberboar", "-write", "-" + flag, "relative"}
		if code := h.run(args, nil, &out, &errb); code != 1 || !strings.Contains(errb.String(), "-"+flag+": can't resolve an absolute path") {
			t.Errorf("%s normalization: exit %d, stderr %s", flag, code, &errb)
		}
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatalf("failed normalization wrote files: %v, %v", entries, err)
	}
}
