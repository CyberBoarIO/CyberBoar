package hook

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/internal/engine"
	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/pkg/sign"
)

// BenchmarkPolicyValidation separates the costs paid by a signed hook.
// These are warm-process timings; a fresh CLI also pays package startup.
func BenchmarkPolicyValidation(b *testing.B) {
	data, err := os.ReadFile("../../examples/baseline.yaml")
	if err != nil {
		b.Fatal(err)
	}
	p, err := policy.Load(data)
	if err != nil {
		b.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	h := sign.Header{Serial: 1, Expires: time.Now().Add(time.Hour).Truncate(time.Second)}
	sig, err := sign.Sign(priv, p.Metadata.Name, data, h)
	if err != nil {
		b.Fatal(err)
	}
	sigBytes := []byte(sig)
	path := filepath.Join(b.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(path+sign.SigSuffix, sigBytes, 0o600); err != nil {
		b.Fatal(err)
	}
	b.Run("signature", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := sign.Verify(pub, p.Metadata.Name, data, sigBytes); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("signature_size_limit", func(b *testing.B) {
		large := append([]byte(nil), data...)
		large = append(large, '#', ' ')
		large = append(large, strings.Repeat("x", policy.MaxSize-len(large)-1)...)
		large = append(large, '\n')
		if _, err := policy.Load(large); err != nil {
			b.Fatal(err)
		}
		signed, err := sign.Sign(priv, p.Metadata.Name, large, h)
		if err != nil {
			b.Fatal(err)
		}
		signedBytes := []byte(signed)
		b.ReportAllocs()
		b.SetBytes(int64(len(large)))
		b.ResetTimer()
		for b.Loop() {
			if _, err := sign.Verify(pub, p.Metadata.Name, large, signedBytes); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("yaml_validation", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := policy.Load(data); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("engine_compile", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := engine.Compile(p); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("signed_load", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			c, _, _, _, err := loadPolicy(Options{PolicyPath: path, PublicKey: pub})
			if c == nil || err != nil {
				b.Fatalf("load failed: %v", err)
			}
		}
	})
}
