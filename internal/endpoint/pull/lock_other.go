//go:build !unix && !windows

package pull

import (
	"errors"
	"io/fs"
	"os"
)

func openInstallLock(string) (*os.File, error) {
	return nil, errors.New("policy installation locking is unsupported on this platform")
}
func tryInstallLock(*os.File) error {
	return errors.New("policy installation locking is unsupported on this platform")
}
func singleLink(*os.File, fs.FileInfo) bool { return false }
