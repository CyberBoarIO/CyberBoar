package atomicfile_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"cyberboar.dev/cyberboar/internal/atomicfile"
)

func TestWriteReplacesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	for _, data := range []string{"old", "new"} {
		if err := atomicfile.Write(path, []byte(data), 0o640); err != nil {
			t.Fatal(err)
		}
		if got, err := os.ReadFile(path); err != nil || string(got) != data {
			t.Fatalf("read %q, %v; want %q", got, err, data)
		}
	}
	if fi, err := os.Stat(path); err != nil || runtime.GOOS != "windows" && fi.Mode().Perm() != 0o640 {
		t.Errorf("mode %v, %v", fi.Mode(), err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("left behind: %v", entries)
	}
	if err := atomicfile.Write(filepath.Join(dir, "missing", "f"), nil, 0o600); err == nil {
		t.Error("wrote into a directory that doesn't exist")
	}
}

func TestWriteNewRefusesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := atomicfile.WriteNew(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicfile.WriteNew(path, []byte("two"), 0o600); !errors.Is(err, fs.ErrExist) {
		t.Errorf("WriteNew over an existing file: %v, want fs.ErrExist", err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "one" {
		t.Errorf("after a refused WriteNew: %q, %v", data, err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 {
		t.Errorf("temporary files after WriteNew: %v, %v", entries, err)
	}
}
