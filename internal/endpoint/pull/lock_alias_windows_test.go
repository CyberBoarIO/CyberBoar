package pull

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestInstallLockWindowsShortName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "long-policy-file-name.yaml")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, 32768)
	n, err := windows.GetShortPathName(p, &buf[0], uint32(len(buf)))
	if err != nil {
		t.Fatal(err)
	}
	short := windows.UTF16ToString(buf[:n])
	if short == path {
		t.Skip("8.3 aliases are disabled on this volume")
	}
	_, unlock, err := lockInstall(path)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, release, err := lockInstall(short); !errors.Is(err, ErrBusy) {
		if release != nil {
			release()
		}
		t.Fatalf("short-name alias used an independent lock: %v", err)
	}
}
