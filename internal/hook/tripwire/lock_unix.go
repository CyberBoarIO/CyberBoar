//go:build unix

package tripwire

import (
	"os"
	"syscall"
)

// openFile opens a state file, refusing a symlink
func openFile(path string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag|syscall.O_NOFOLLOW, perm)
}

// lockShared and lockExclusive take flock locks. The kernel releases them when
// the file is closed or the process dies, so a crashed hook never wedges a
// session
func lockShared(f *os.File) error    { return syscall.Flock(int(f.Fd()), syscall.LOCK_SH) }
func lockExclusive(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX) }
