//go:build windows

package ship

import (
	"fmt"
	"os"
	"syscall"
)

// fileID identifies the file f is open on whatever its name: its volume's
// serial number and its file index, which a rename keeps.
func fileID(f *os.File) (string, error) {
	var d syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(syscall.Handle(f.Fd()), &d); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x:%x%08x", d.VolumeSerialNumber, d.FileIndexHigh, d.FileIndexLow), nil
}
