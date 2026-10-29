package osfs

import (
	"path/filepath"
	"syscall"
)

// longName asks Windows for the long form of op's last name
// (GetLongPathNameW), which expands 8.3 short names.
func longName(op string) (string, error) {
	p, err := syscall.UTF16PtrFromString(op)
	if err != nil {
		return "", err
	}
	buf := make([]uint16, 512)
	for {
		// #nosec G115 -- buf holds 512 or n, a uint32, elements
		n, err := syscall.GetLongPathName(p, &buf[0], uint32(len(buf)))
		if err != nil {
			return "", err
		}
		// #nosec G115 -- buf holds 512 or n, a uint32, elements
		if n <= uint32(len(buf)) {
			return filepath.Base(syscall.UTF16ToString(buf[:n])), nil
		}
		buf = make([]uint16, n)
	}
}
