package pull

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/pkg/sign"
)

// TestInstallLockProcessHelper holds a real kernel lock in a subprocess
func TestInstallLockProcessHelper(t *testing.T) {
	out := os.Getenv("CYBERBOAR_TEST_LOCK_OUT")
	if out == "" {
		return
	}
	_, unlock, err := lockInstall(out)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := io.WriteString(os.Stdout, "locked\n"); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func TestInstallLockAcrossProcesses(t *testing.T) {
	out := filepath.Join(t.TempDir(), "policy.yaml")
	cmd := exec.Command(os.Args[0], "-test.run=^TestInstallLockProcessHelper$")
	cmd.Env = append(os.Environ(), "CYBERBOAR_TEST_LOCK_OUT="+out)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "locked\n" {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("child lock: %q, %v (%s)", line, err, &stderr)
	}
	if changed, err := install(out, nil, nil, sign.Header{Serial: 1}); !errors.Is(err, ErrBusy) || changed {
		t.Fatalf("concurrent process: %v, %v", changed, err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(filepath.Dir(out), alias); err == nil {
		if _, _, err := lockInstall(filepath.Join(alias, filepath.Base(out))); !errors.Is(err, ErrBusy) {
			t.Fatalf("directory alias: %v", err)
		}
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	_ = cmd.Wait()
	_, unlock, err := lockInstall(out)
	if err != nil {
		t.Fatalf("lock after crashed writer: %v (%s)", err, &stderr)
	}
	unlock()
	if _, err := os.Stat(out + ".lock"); err != nil {
		t.Fatal("persistent lock was removed", err)
	}
}

func TestInstallLockRefusesAliases(t *testing.T) {
	for _, leaf := range []string{".lock", "", ".sig"} {
		t.Run(strings.ReplaceAll(leaf, ".", "dot"), func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "policy.yaml")
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, out+leaf); err != nil {
				t.Skip(err)
			}
			if changed, err := install(out, nil, nil, sign.Header{Serial: 1}); err == nil || changed {
				t.Fatal("installed through a leaf alias")
			}
			if data, _ := os.ReadFile(target); string(data) != "untouched" {
				t.Fatal("modified alias target")
			}
		})
	}
}

func TestInstallLockRefusesHardLinks(t *testing.T) {
	out := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(out+".lock", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(out+".lock", filepath.Join(t.TempDir(), "alias.lock")); err != nil {
		t.Skip(err)
	}
	if _, unlock, err := lockInstall(out); err == nil {
		unlock()
		t.Fatal("accepted a lock with another link")
	}
}
