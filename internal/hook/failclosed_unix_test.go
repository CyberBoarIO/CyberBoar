//go:build unix

package hook_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/internal/hook"
)

// An audit write that hangs (a stale network home directory) must not
// outlast the agent's hook timeout, which fails open. A FIFO nobody reads
// blocks the real write the same way: opening it for writing waits for a
// reader.
func TestAuditWriteDeadline(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// A reader lets the blocked writer finish, so its goroutine ends with
		// the test. O_NONBLOCK keeps this open from waiting if no writer came.
		if f, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
			f.Close()
		}
	})

	o := hook.Options{Adapter: cc, StateDir: t.TempDir(), PolicyPath: policyFile(t, baselinePolicy(t), nil), Getenv: env, AuditPath: fifo}
	const margin = 3 * time.Second
	done := make(chan hook.Result, 1)
	start := time.Now()
	go func() { done <- hook.Run(context.Background(), strings.NewReader(bashLS), o) }()
	select {
	case r := <-done:
		assertDenied(t, r, hook.RuleAudit)
		if took := time.Since(start); took > hook.AuditLimit+margin {
			t.Errorf("answered after %s; it must not wait for a hung audit write", took)
		}
	case <-time.After(hook.AuditLimit + margin):
		t.Fatalf("no answer within %s: the hung audit write holds up the hook", hook.AuditLimit+margin)
	}
}
