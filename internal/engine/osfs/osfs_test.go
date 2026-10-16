package osfs_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"cyberboar.dev/cyberboar/internal/engine/osfs"
)

func TestReadDirLimit(t *testing.T) {
	dir := t.TempDir()
	for i := osfs.MaxDirEntries - 1; i >= 0; i-- {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("entry-%05d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f := osfs.FS{}
	entries, err := f.ReadDir(dir)
	if err != nil || len(entries) != osfs.MaxDirEntries {
		t.Fatalf("boundary: %d, %v", len(entries), err)
	}
	if entries[0].Name() != "entry-00000" || entries[len(entries)-1].Name() != "entry-49999" {
		t.Fatal("enumeration is not sorted")
	}
	if err := os.WriteFile(filepath.Join(dir, "extra"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if entries, err := f.ReadDir(dir); !errors.Is(err, osfs.ErrTooLarge) || entries != nil {
		t.Fatalf("oversized directory: %d, %v", len(entries), err)
	}
}
