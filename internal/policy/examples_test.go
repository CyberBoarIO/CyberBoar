package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"cyberboar.dev/cyberboar/internal/policy"
)

// Example policies are documentation users copy from; each must load.
// This also catches a stale apiVersion after a rename.
func TestExamplePoliciesLoad(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "examples", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no example policies found (err=%v)", err)
	}
	for _, path := range files {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := policy.Load(data); err != nil {
				t.Fatal(err)
			}
		})
	}
}
