//go:build unix

package hook_test

import (
	"context"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/internal/adapters/claudecode"
	"cyberboar.dev/cyberboar/internal/hook"
)

func TestSigningKeyFIFO(t *testing.T) {
	key := filepath.Join(t.TempDir(), "key")
	if err := syscall.Mkfifo(key, 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	r := hook.Run(context.Background(), strings.NewReader(bashLS), hook.Options{
		Adapter: claudecode.Adapter{}, Getenv: env, PolicyPath: policyFile(t, baselinePolicy(t), nil),
		PublicKeyPath: key, Deadline: 10 * time.Millisecond,
	})
	assertDenied(t, r, hook.RuleHookSetup)
	if time.Since(start) > time.Second {
		t.Fatal("public-key FIFO exceeded the deadline margin")
	}
}
