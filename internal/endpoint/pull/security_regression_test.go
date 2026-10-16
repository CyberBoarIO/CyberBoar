package pull

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/pkg/sign"
)

// TestConcurrentInstallSerialFloor checks whether concurrent checked bundles can
// leave a lower serial than an install that succeeded in the same batch.
func TestConcurrentInstallSerialFloor(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../../examples/baseline.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Load(data)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 100; attempt++ {
		out := filepath.Join(t.TempDir(), "policy.yaml")
		start := make(chan struct{})
		var wg sync.WaitGroup
		var mu sync.Mutex
		var maximum uint64
		for serial := uint64(1); serial <= 16; serial++ {
			h := sign.Header{Serial: serial}
			sig, err := sign.Sign(priv, p.Metadata.Name, data, h)
			if err != nil {
				t.Fatal(err)
			}
			wg.Go(func() {
				<-start
				if _, err := install(out, data, []byte(sig), h); err == nil {
					mu.Lock()
					if h.Serial > maximum {
						maximum = h.Serial
					}
					mu.Unlock()
				}
			})
		}
		close(start)
		wg.Wait()
		sig, err := sign.ReadSig(out)
		if err != nil {
			t.Fatal(err)
		}
		installed, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		h, err := sign.Verify(pub, p.Metadata.Name, installed, sig)
		if err != nil {
			t.Fatalf("concurrent successful installs left an invalid pair: %v", err)
		}
		if h.Serial < maximum {
			t.Fatalf("confirmed rollback: final serial %d below successful install %d (attempt %d)", h.Serial, maximum, attempt)
		}
	}
}
