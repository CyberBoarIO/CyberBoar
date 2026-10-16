package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/internal/protocoltest"
	"cyberboar.dev/cyberboar/pkg/sign"
)

func TestInstalledPullIntervalTrust(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, tc := range []struct {
		name, policyName string
		expiry           time.Time
		tamper, unsigned bool
		valid            bool
	}{
		{name: "valid", policyName: "baseline", expiry: now.Add(time.Hour), valid: true},
		{name: "expired", policyName: "baseline", expiry: now.Add(-time.Hour)},
		{name: "wrong name", policyName: "other", expiry: now.Add(time.Hour)},
		{name: "tampered", policyName: "baseline", expiry: now.Add(time.Hour), tamper: true},
		{name: "unsigned", policyName: "baseline", expiry: now.Add(time.Hour), unsigned: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.yaml")
			data := []byte(fmt.Sprintf("apiVersion: cyberboar.dev/v1\nkind: Policy\nmetadata: {name: %s}\nspec: {sync: {pullEvery: 4h}}\n", tc.policyName))
			sig, err := sign.Sign(priv, tc.policyName, data, sign.Header{Serial: 1, Expires: tc.expiry.Truncate(time.Second)})
			if err != nil {
				t.Fatal(err)
			}
			if tc.tamper {
				data = []byte(strings.ReplaceAll(string(data), "4h", "10s"))
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if !tc.unsigned {
				if err := os.WriteFile(path+sign.SigSuffix, []byte(sig), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			d, err := installedPullInterval(path, "baseline", pub, now)
			if tc.valid {
				if err != nil || d != 4*time.Hour {
					t.Fatalf("interval = %s, %v; want 4h", d, err)
				}
			} else if err == nil {
				t.Fatal("untrusted policy supplied a refresh interval")
			}
		})
	}
}

func TestSyncCommandProcess(t *testing.T) {
	if os.Getenv("CYBERBOAR_TEST_SYNC_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Exit(host{getenv: os.Getenv, goos: runtime.GOOS, now: time.Now}.run(os.Args[i+1:], strings.NewReader(""), os.Stdout, os.Stderr))
		}
	}
	os.Exit(2)
}

func startSyncCommand(t *testing.T, args ...string) (*exec.Cmd, <-chan error, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	t.Cleanup(cancel)
	outputPath := filepath.Join(t.TempDir(), "output.txt")
	output, err := os.Create(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = output.Close() })
	cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestSyncCommandProcess$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "CYBERBOAR_TEST_SYNC_PROCESS=1", "CYBERBOAR_POLICY=", "CYBERBOAR_SINK=", "CYBERBOAR_SERVER=")
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	return cmd, done, outputPath
}

func waitForSync(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for policy sync")
}

func waitSyncExit(t *testing.T, done <-chan error, outputPath string) string {
	t.Helper()
	select {
	case err := <-done:
		output, readErr := os.ReadFile(outputPath)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if err != nil {
			t.Fatalf("sync command: %v\n%s", err, output)
		}
		return string(output)
	case <-time.After(20 * time.Second):
		output, _ := os.ReadFile(outputPath)
		t.Fatalf("sync command did not exit\n%s", output)
		return ""
	}
}

func TestShipPolicyIntervalAndOverride(t *testing.T) {
	console := protocoltest.New(t, "", nil)
	c := newCLI(t)
	c.enroll(console, "baseline")
	state := filepath.Join(c.home, ".local", "state", "cyberboar")
	policyPath, auditPath := filepath.Join(c.home, "policy.yaml"), filepath.Join(c.home, "audit.jsonl")
	writePolicy := func(every string) {
		t.Helper()
		data := fmt.Sprintf("apiVersion: cyberboar.dev/v1\nkind: Policy\nmetadata: {name: baseline}\nspec: {audit: {sink: %q}, sync: {shipEvery: %s}}\n", console.URL+"/api/v1/events", every)
		if err := os.WriteFile(policyPath, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writePolicy("1s")
	if err := os.WriteFile(auditPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	appendLine(t, auditPath)
	args := []string{"ship", "--audit", auditPath, "--policy", policyPath, "--state", state, "--ca", console.CAFile(t)}
	_, done, output := startSyncCommand(t, args...)
	waitForSync(t, func() bool { return len(console.Batches()) == 1 })
	appendLine(t, auditPath)
	waitForSync(t, func() bool { return len(console.Batches()) == 2 })
	// At least one idle round must be silent while the service is running.
	time.Sleep(1200 * time.Millisecond)
	idleOutput, err := os.ReadFile(output)
	if err != nil || strings.Contains(string(idleOutput), "shipped 0 events") {
		t.Fatalf("idle service output: %s (%v)", idleOutput, err)
	}
	// The next round stops the service when the policy changes to one run.
	writePolicy("0s")
	waitSyncExit(t, done, output)
	writePolicy("1s")
	_, done, output = startSyncCommand(t, append(args, "--every", "0s")...)
	if got := waitSyncExit(t, done, output); !strings.Contains(got, "shipped 0 events") {
		t.Fatalf("one-run override output: %s", got)
	}
}

func TestPullUsesFirstInstalledPolicyInterval(t *testing.T) {
	c := newCLI(t)
	private, public := filepath.Join(c.home, "key"), filepath.Join(c.home, "key.pub")
	if err := sign.Keygen(private, public); err != nil {
		t.Fatal(err)
	}
	policies := filepath.Join(c.home, "policies")
	if err := os.Mkdir(policies, 0o700); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(policies, "baseline.yaml")
	writePolicy := func(every, serial string) {
		t.Helper()
		data := fmt.Sprintf("apiVersion: cyberboar.dev/v1\nkind: Policy\nmetadata: {name: baseline}\nspec: {sync: {pullEvery: %s}}\n", every)
		if err := os.WriteFile(policyPath, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if code := c.run("", "sign", "--key", private, "--serial", serial, "--expires", "1h", policyPath); code != 0 {
			t.Fatal(c.err.String())
		}
	}
	writePolicy("10s", "1")
	pub, err := sign.LoadPublic(public)
	if err != nil {
		t.Fatal(err)
	}
	console := protocoltest.New(t, policies, pub)
	c.enroll(console, "baseline")
	state := filepath.Join(c.home, ".local", "state", "cyberboar")
	out := filepath.Join(c.home, "installed.yaml")
	args := []string{"pull", "--out", out, "--pubkey", public, "--state", state, "--ca", console.CAFile(t)}
	_, done, output := startSyncCommand(t, args...)
	waitForSync(t, func() bool { _, err := os.Stat(out); return err == nil })
	// No --every was supplied; the first downloaded policy must have started
	// polling. Its next signed revision turns polling off without a restart.
	writePolicy("0s", "2")
	console.Reload(t)
	got := waitSyncExit(t, done, output)
	data, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(data), "pullEvery: 0s") || strings.Count(got, "installed policy baseline") != 2 {
		t.Fatalf("next revision was not installed: %s\n%s (%v)", got, data, err)
	}
	writePolicy("10s", "3")
	console.Reload(t)
	_, done, output = startSyncCommand(t, append(args, "--every", "0s")...)
	waitSyncExit(t, done, output)
}
