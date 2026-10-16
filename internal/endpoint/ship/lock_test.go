package ship

import (
	"errors"
	"testing"
)

func TestLockIsExclusive(t *testing.T) {
	dir := t.TempDir()
	unlock, err := lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lock(dir); !errors.Is(err, ErrBusy) {
		t.Fatalf("second lock: %v, want ErrBusy", err)
	}
	unlock()
	unlock, err = lock(dir)
	if err != nil {
		t.Fatalf("lock after unlock: %v", err)
	}
	unlock()
}
