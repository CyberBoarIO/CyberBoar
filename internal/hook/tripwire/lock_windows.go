package tripwire

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

var errNotRegular = errors.New("tripwire state file is not a regular file, or was replaced while it was opened")

// openFile opens a state file, refusing a symlink. Windows has no
// O_NOFOLLOW, so the path is checked before the open, which keeps O_CREATE
// from creating a link's target, and the open file is compared with the path
// after it, which catches a link swapped in between
func openFile(path string, flag int, perm os.FileMode) (*os.File, error) {
	if lst, err := os.Lstat(path); err == nil && !lst.Mode().IsRegular() {
		return nil, errNotRegular
	}
	f, err := os.OpenFile(path, flag, perm)
	if err != nil {
		return nil, err
	}
	lst, err1 := os.Lstat(path)
	fst, err2 := f.Stat()
	if err1 != nil || err2 != nil || !lst.Mode().IsRegular() || !os.SameFile(lst, fst) {
		f.Close()
		return nil, errNotRegular
	}
	return f, nil
}

// lockOffset is where the lock byte lies, far past the end of any state
// file. Windows locks are mandatory, so a lock over the contents would make
// reads through other handles fail, such as List's
const lockOffset = 1 << 62

// lockShared and lockExclusive wait for a LockFileEx lock on the byte at
// lockOffset. Windows releases it when the handle is closed or the process
// dies, so a crashed hook never wedges a session
func lockShared(f *os.File) error    { return lockFile(f, 0) }
func lockExclusive(f *os.File) error { return lockFile(f, windows.LOCKFILE_EXCLUSIVE_LOCK) }

func lockFile(f *os.File, flags uint32) error {
	ol := windows.Overlapped{Offset: uint32(lockOffset & 0xFFFFFFFF), OffsetHigh: uint32(lockOffset >> 32)}
	return windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, 1, 0, &ol)
}
