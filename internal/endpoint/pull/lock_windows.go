package pull

import (
	"errors"
	"io/fs"
	"os"

	"golang.org/x/sys/windows"
)

func openInstallLock(path string) (*os.File, error) {
	// Go's Windows file open shares read and write, but not delete: a held
	// lock handle therefore prevents unlinking or replacing the lock file
	// #nosec G703 -- lockInstall derives this from the explicit local destination
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
}

func tryInstallLock(f *os.File) error {
	err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, new(windows.Overlapped))
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return ErrBusy
	}
	return err
}

func singleLink(f *os.File, info fs.FileInfo) bool {
	var data windows.ByHandleFileInformation
	return info.Mode().IsRegular() && windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &data) == nil && data.NumberOfLinks == 1
}
