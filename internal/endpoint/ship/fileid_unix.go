//go:build unix

package ship

import (
	"fmt"
	"os"
	"syscall"
)

// fileID identifies the file f is open on whatever its name: its device and
// inode, which a rename keeps.
func fileID(f *os.File) (string, error) {
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", nil
	}
	return fmt.Sprintf("%d:%d", st.Dev, st.Ino), nil
}
