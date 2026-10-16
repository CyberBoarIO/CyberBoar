//go:build unix

package pull

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

func openInstallLock(path string) (*os.File, error) {
	// #nosec G703 -- lockInstall derives this from the explicit local destination
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
}

func tryInstallLock(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return ErrBusy
		}
		return err
	}
	return nil
}

func singleLink(_ *os.File, info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}
