package ship

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// lock takes an exclusive, non-blocking lock on stateDir/ship.lock. Windows
// releases it when the handle is closed or the process dies, so a crash
// never wedges shipping.
func lock(stateDir string) (unlock func(), err error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(stateDir, "ship.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, new(windows.Overlapped))
	if err != nil {
		f.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, ErrBusy
		}
		return nil, err
	}
	return func() { f.Close() }, nil
}
