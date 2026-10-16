package enroll

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"cyberboar.dev/cyberboar/pkg/endpointauth"
)

func TestEndpointIDIsStableAndNeverReplaced(t *testing.T) {
	dir := t.TempDir()
	id, err := EndpointID(dir)
	if err != nil || !endpointauth.ValidEndpointID(id) {
		t.Fatalf("EndpointID = %q, %v", id, err)
	}
	again, _ := EndpointID(dir)
	if again != id {
		t.Error("the ID is not stable")
	}
	fi, _ := os.Stat(filepath.Join(dir, "endpoint-id"))
	// Windows has no mode bits; the state directory's DACL protects the
	// file there (TestWindowsACL).
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("endpoint-id mode %v", fi.Mode().Perm())
	}
	os.WriteFile(filepath.Join(dir, "endpoint-id"), []byte("not-an-id\n"), 0o600)
	if _, err := EndpointID(dir); err == nil {
		t.Error("a corrupt endpoint ID was accepted or replaced")
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "endpoint-id")); string(got) != "not-an-id\n" {
		t.Error("a corrupt endpoint ID was overwritten")
	}
}

func TestNewUUIDIsVersion4(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		id := newUUID()
		if !endpointauth.ValidEndpointID(id) || seen[id] {
			t.Fatalf("bad or repeated UUID %q", id)
		}
		seen[id] = true
	}
}

func TestEndpointIDConcurrentFirstUse(t *testing.T) {
	const workers = 64
	type result struct {
		id  string
		err error
	}
	for range 10 {
		dir := t.TempDir()
		start := make(chan struct{})
		results := make(chan result, workers)
		for range workers {
			go func() {
				<-start
				id, err := EndpointID(dir)
				results <- result{id, err}
			}()
		}
		close(start)
		first := ""
		for range workers {
			r := <-results
			if r.err != nil || !endpointauth.ValidEndpointID(r.id) {
				t.Errorf("concurrent EndpointID = %q, %v", r.id, r.err)
				continue
			}
			if first == "" {
				first = r.id
			}
			if r.id != first {
				t.Errorf("concurrent callers got different IDs: %q and %q", first, r.id)
			}
		}
		if t.Failed() {
			t.FailNow()
		}
	}
}
